import tkinter as tk
from tkinter import messagebox, ttk # messagebox is now only used in ui.py
import re
import random
import time
import base64
import os

from firebase_service import FirebaseService, check_hashed_value # Import check_hashed_value
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


# --- Encryption Utilities ---
def derive_encryption_key(master_password: str, salt_b64: str) -> bytes:
    """Derives a Fernet-compatible key from master password and salt."""
    if not master_password or not salt_b64:
        raise ValueError("Master password and salt are required for key derivation.")
    salt_bytes = base64.urlsafe_b64decode(salt_b64.encode('utf-8'))
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt_bytes,
        iterations=390000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode('utf-8')))
    return key

class EncryptionService:
    def __init__(self, derived_key: bytes):
        if not derived_key:
            raise ValueError("Encryption key cannot be empty.")
        self.fernet = Fernet(derived_key)

    def encrypt(self, plain_text_data: str) -> str:
        if plain_text_data is None: return None
        return self.fernet.encrypt(plain_text_data.encode('utf-8')).decode('utf-8')

    def decrypt(self, encrypted_data_str: str) -> str:
        if not encrypted_data_str: return ""
        try:
            return self.fernet.decrypt(encrypted_data_str.encode('utf-8')).decode('utf-8')
        except InvalidToken:
            print("Decryption failed: Invalid token or key.")
            raise
        except Exception as e:
            print(f"An unexpected error occurred during decryption: {e}")
            raise


class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager (Firebase - Production Secure)")
        self.root.geometry("950x700")
        self.root.configure(bg="#e8ecef")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.firebase_service = FirebaseService(credentials_path="serviceAccountKey.json")
        # Check if Firebase initialized correctly in the service
        if not self.firebase_service.db:
            # The print from FirebaseService's __init__ would have already occurred in the console
            messagebox.showerror("Startup Error",
                                 "Failed to connect to Firebase (see console for details). "
                                 "Application features will be limited or non-functional.")
            # Optionally, you could disable UI elements or self.root.quit()
            # if Firebase is absolutely essential for any operation from the start.

        self.primary_color = "#2c5282"; self.secondary_color = "#3182ce"; self.accent_color = "#90cdf4"
        self.bg_color = "#e8ecef"; self.text_color = "#1a202c"; self.error_color = "#e53e3e"
        self.success_color = "#38a169"; self.warning_color = "#d69e2e"; self.entry_bg_color = "#ffffff"
        self.entry_fg_color = self.text_color

        self.configure_styles()

        self.current_user = None
        self.encryption_service = None
        self.editing_password = None
        self.form_history = []
        self.is_loading = False

        self.create_login_form()
        self.create_register_form()
        self.create_recovery_form()
        self.create_dashboard()
        self.create_edit_profile_form()
        self.create_add_password_form()
        self.create_edit_password_form()

        self.show_form("login")

    def configure_styles(self):
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('TFrame', background=self.bg_color)
        self.style.configure('TLabel', background=self.bg_color, foreground=self.text_color, font=('Segoe UI', 11))
        self.style.configure('Title.TLabel', font=('Segoe UI', 20, 'bold'), foreground=self.primary_color, padding=(0, 10, 0, 10))
        self.style.configure('Header.TFrame', background=self.bg_color)
        self.style.configure('Form.TFrame', background=self.bg_color)
        self.style.configure('TButton', font=('Segoe UI', 11, 'bold'), borderwidth=0, padding=10, relief='flat', anchor='center')
        self.style.map('TButton', foreground=[('!active', self.text_color), ('active', self.text_color)], background=[('!active', self.accent_color), ('active', self.secondary_color)])
        self.style.configure('Primary.TButton', background=self.primary_color, foreground='white')
        self.style.map('Primary.TButton', background=[('active', self.secondary_color)])
        self.style.configure('Secondary.TButton', background=self.secondary_color, foreground='white')
        self.style.map('Secondary.TButton', background=[('active', self.primary_color)])
        self.style.configure('Danger.TButton', background=self.error_color, foreground='white')
        self.style.map('Danger.TButton', background=[('active', '#c53030')])
        self.style.configure('TEntry', fieldbackground=self.entry_bg_color, foreground=self.entry_fg_color, padding=8, relief='flat', borderwidth=1, bordercolor=self.secondary_color)
        self.style.map('TEntry', bordercolor=[('focus', self.primary_color)], lightcolor=[('focus', self.primary_color)])
        self.style.configure('Error.TEntry', foreground=self.error_color, fieldbackground='#fee2e2')
        self.style.configure('TCheckbutton', background=self.bg_color, foreground=self.text_color, font=('Segoe UI', 10))
        self.style.map('TCheckbutton', indicatorcolor=[('selected', self.primary_color), ('!selected', self.entry_bg_color)], foreground=[('active', self.primary_color)])
        self.style.configure('Treeview', background=self.entry_bg_color, fieldbackground=self.entry_bg_color, foreground=self.text_color, font=('Segoe UI', 10), rowheight=30)
        self.style.configure('Treeview.Heading', background=self.primary_color, foreground='white', font=('Segoe UI', 11, 'bold'), padding=(10, 5), relief='flat')
        self.style.map('Treeview.Heading', relief=[('active','groove')])
        self.style.map('Treeview', background=[('selected', self.secondary_color)], foreground=[('selected', 'white')])
        self.style.configure('Vertical.TScrollbar', background=self.primary_color, troughcolor=self.bg_color, bordercolor=self.primary_color, arrowcolor='white')
        self.style.map('Vertical.TScrollbar', background=[('active', self.secondary_color)])

        # Styles for info/error rows in Treeview
        self.style.configure("info_row.Treeview", foreground="gray") # For ttk.Treeview items
        self.style.configure("info_row_error.Treeview", foreground=self.error_color)


    def on_closing(self):
        if messagebox.askokcancel("Quit", "Do you want to quit Password Manager?"):
            self.current_user = None
            self.encryption_service = None
            self.root.destroy()

    def show_form(self, form_name):
        valid_forms = ["login", "register", "recover", "dashboard", "edit_profile", "add_password", "edit_password"]
        if form_name not in valid_forms:
            print(f"Error: Attempted to show invalid form '{form_name}'")
            return

        # Crucial check for Firebase connection before showing forms that need it
        if not self.firebase_service.db and form_name not in ["login", "register", "recover"]:
             messagebox.showerror("Database Error", "Firebase is not connected. Cannot access this page.")
             if self.current_user: # If user was logged in but connection dropped somehow
                 self.logout(silent=True) # Log out without confirmation if DB is gone
             self.show_form("login") # Fallback to login
             return

        if not self.form_history or self.form_history[-1] != form_name:
             self.form_history.append(form_name)

        for frame_attr_name in [
            "login_frame", "register_frame", "recover_frame", "dashboard_frame",
            "edit_profile_frame", "add_password_frame", "edit_password_frame"
        ]:
            frame = getattr(self, frame_attr_name, None)
            if frame: frame.pack_forget()

        target_frame = getattr(self, f"{form_name}_frame")
        target_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        if form_name == "dashboard":
            if self.current_user and self.encryption_service:
                self.refresh_password_list()
            else:
                # Clear tree and show appropriate message if trying to access dashboard without being logged in
                for item in self.tree.get_children(): self.tree.delete(item)
                if not self.tree.exists("INFO_NO_LOGIN_DASH"):
                    self.tree.insert('', tk.END, iid="INFO_NO_LOGIN_DASH", values=("", "Please log in to view passwords.", "", ""), tags=("info_row",))
            self.search_entry.focus_set()
        elif form_name == "edit_profile":
            self.load_profile_data()
            self.edit_username.focus_set()
        elif form_name == "add_password":
            self.add_app_name.focus_set()

    def go_back(self):
        if len(self.form_history) > 1:
            self.form_history.pop(); previous_form = self.form_history[-1]; self.form_history.pop()
            self.show_form(previous_form)
        elif len(self.form_history) == 1 and self.form_history[0] != "login":
             self.form_history.pop(); self.show_form("login")

    def create_login_form(self):
        self.login_frame = ttk.Frame(self.root, style='TFrame', name='login_frame')
        self.login_frame.columnconfigure(0, weight=1)
        header = ttk.Frame(self.login_frame, style='Header.TFrame'); header.grid(row=0, column=0, pady=(40, 20), sticky="ew"); header.columnconfigure(0, weight=1)
        ttk.Label(header, text="🔒 Login to Your Vault", style='Title.TLabel').grid(row=0, column=0)
        form = ttk.Frame(self.login_frame, style='Form.TFrame', width=400); form.grid(row=1, column=0, padx=20, pady=10, sticky="n"); form.columnconfigure(0, weight=1)
        ttk.Label(form, text="Email").grid(row=0, column=0, columnspan=2, sticky="w", pady=(10, 2))
        self.login_email_var = tk.StringVar(); self.login_email = ttk.Entry(form, textvariable=self.login_email_var, width=40)
        self.login_email.grid(row=1, column=0, columnspan=2, sticky="ew", pady=5)
        self.login_email.bind("<KeyRelease>", lambda e: self.validate_field(self.login_email_var, self.login_email, 'email'))
        self.login_email.bind("<Return>", lambda e: self.login_password.focus_set())
        ttk.Label(form, text="Password").grid(row=2, column=0, columnspan=2, sticky="w", pady=(10, 2))
        self.login_password_var = tk.StringVar(); self.login_password = ttk.Entry(form, textvariable=self.login_password_var, show="•", width=40)
        self.login_password.grid(row=3, column=0, sticky="ew", pady=5)
        self.login_show_password_var = tk.BooleanVar(value=False)
        self.login_show_password = ttk.Checkbutton(form, text="Show", variable=self.login_show_password_var, command=lambda: self.toggle_password(self.login_password, self.login_show_password_var), style='TCheckbutton')
        self.login_show_password.grid(row=3, column=1, padx=(10,0), sticky='w')
        self.login_password.bind("<Return>", lambda e: self.login())
        self.login_button = ttk.Button(form, text="Login", style='Primary.TButton', command=self.login, width=15)
        self.login_button.grid(row=4, column=0, columnspan=2, pady=(30, 10))
        link_frame = ttk.Frame(form, style='Form.TFrame'); link_frame.grid(row=5, column=0, columnspan=2, pady=(10, 20), sticky="ew"); link_frame.columnconfigure(0, weight=1); link_frame.columnconfigure(1, weight=1)
        reg_button = ttk.Button(link_frame, text="Register New Account", style='Secondary.TButton', command=lambda: self.show_form("register")); reg_button.grid(row=0, column=0, sticky="ew", padx=5)
        rec_button = ttk.Button(link_frame, text="Forgot Password?", style='Secondary.TButton', command=lambda: self.show_form("recover")); rec_button.grid(row=0, column=1, sticky="ew", padx=5)

    def create_register_form(self):
        self.register_frame = ttk.Frame(self.root, style='TFrame', name='register_frame'); self.register_frame.columnconfigure(0, weight=1)
        header = ttk.Frame(self.register_frame, style='Header.TFrame'); header.grid(row=0, column=0, pady=(40, 20), sticky="ew"); header.columnconfigure(0, weight=1)
        ttk.Label(header, text="👤 Create Your Account", style='Title.TLabel').grid(row=0, column=0, sticky='w', padx=20)
        ttk.Button(header, text="← Back", style='Secondary.TButton', command=self.go_back).grid(row=0, column=1, sticky="e", padx=20)
        form = ttk.Frame(self.register_frame, style='Form.TFrame', width=450); form.grid(row=1, column=0, padx=20, pady=10, sticky="n"); form.columnconfigure(0, weight=1)
        ttk.Label(form, text="Full Name").grid(row=0, column=0, columnspan=2, sticky="w", pady=(10, 2))
        self.register_name_var = tk.StringVar(); self.register_name = ttk.Entry(form, textvariable=self.register_name_var, width=50)
        self.register_name.grid(row=1, column=0, columnspan=2, sticky="ew", pady=5); self.register_name.bind("<KeyRelease>", lambda e: self.validate_field(self.register_name_var, self.register_name, 'non_empty')); self.register_name.bind("<Return>", lambda e: self.register_email.focus_set())
        ttk.Label(form, text="Email Address").grid(row=2, column=0, columnspan=2, sticky="w", pady=(10, 2))
        self.register_email_var = tk.StringVar(); self.register_email = ttk.Entry(form, textvariable=self.register_email_var, width=50)
        self.register_email.grid(row=3, column=0, columnspan=2, sticky="ew", pady=5); self.register_email.bind("<KeyRelease>", lambda e: self.validate_field(self.register_email_var, self.register_email, 'email')); self.register_email.bind("<Return>", lambda e: self.register_password.focus_set())
        ttk.Label(form, text="Choose a Strong Password").grid(row=4, column=0, columnspan=2, sticky="w", pady=(10, 2))
        self.register_password_var = tk.StringVar(); self.register_password = ttk.Entry(form, textvariable=self.register_password_var, show="•", width=50)
        self.register_password.grid(row=5, column=0, sticky="ew", pady=5); self.register_show_password_var = tk.BooleanVar(value=False)
        self.register_show_password = ttk.Checkbutton(form, text="Show", variable=self.register_show_password_var, command=lambda: self.toggle_password(self.register_password, self.register_show_password_var)); self.register_show_password.grid(row=5, column=1, padx=(10,0), sticky='w')
        self.register_password.bind("<KeyRelease>", lambda e: self.validate_password_strength()); self.register_password.bind("<Return>", lambda e: self.register_pin.focus_set())
        self.password_strength_frame = ttk.Frame(form, style='Form.TFrame'); self.password_strength_frame.grid(row=6, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        self.password_strength_bar = ttk.Progressbar(self.password_strength_frame, orient='horizontal', length=100, mode='determinate'); self.password_strength_bar.grid(row=0, column=0, sticky='ew', padx=(0, 5))
        self.password_strength_label = ttk.Label(self.password_strength_frame, text="Strength: -", font=('Segoe UI', 9)); self.password_strength_label.grid(row=0, column=1, sticky='w'); self.password_strength_frame.columnconfigure(0, weight=1)
        ttk.Label(form, text="Set a 4-digit PIN (Optional)").grid(row=7, column=0, columnspan=2, sticky="w", pady=(10, 2))
        self.register_pin_var = tk.StringVar(); validate_pin_cmd_reg = self.root.register(lambda P: P.isdigit() and len(P) <= 4 or P == "")
        self.register_pin = ttk.Entry(form, textvariable=self.register_pin_var, show="•", width=10, validate='key', validatecommand=(validate_pin_cmd_reg, '%P'))
        self.register_pin.grid(row=8, column=0, sticky="w", pady=5)
        self.register_show_pin_var = tk.BooleanVar(value=False)
        self.register_show_pin_check = ttk.Checkbutton(form, text="Show", variable=self.register_show_pin_var, command=lambda: self.toggle_password(self.register_pin, self.register_show_pin_var))
        self.register_show_pin_check.grid(row=8, column=1, padx=(0,0), sticky='w')
        self.register_pin.bind("<Return>", lambda e: self.register())
        self.register_button = ttk.Button(form, text="Register", style='Primary.TButton', command=self.register, width=15); self.register_button.grid(row=9, column=0, columnspan=2, pady=(20, 10))

    def create_recovery_form(self):
        self.recover_frame = ttk.Frame(self.root, style='TFrame', name='recover_frame'); self.recover_frame.columnconfigure(0, weight=1)
        header = ttk.Frame(self.recover_frame, style='Header.TFrame'); header.grid(row=0, column=0, pady=(40, 20), sticky="ew"); header.columnconfigure(0, weight=1)
        ttk.Label(header, text="🔑 Recover Your Account", style='Title.TLabel').grid(row=0, column=0, sticky='w', padx=20)
        ttk.Button(header, text="← Back", style='Secondary.TButton', command=self.go_back).grid(row=0, column=1, sticky="e", padx=20)
        form = ttk.Frame(self.recover_frame, style='Form.TFrame', width=450); form.grid(row=1, column=0, padx=20, pady=10, sticky="n"); form.columnconfigure(0, weight=1)
        ttk.Label(form, text="Enter your registered Email or Recovery Email:").grid(row=0, column=0, sticky="w", pady=(10, 2))
        self.recovery_email_var = tk.StringVar(); self.recovery_email = ttk.Entry(form, textvariable=self.recovery_email_var, width=50)
        self.recovery_email.grid(row=1, column=0, sticky="ew", pady=5); self.recovery_email.bind("<KeyRelease>", lambda e: self.validate_field(self.recovery_email_var, self.recovery_email, 'email')); self.recovery_email.bind("<Return>", lambda e: self.recover_account())
        self.recover_button = ttk.Button(form, text="Send Recovery Instructions", style='Primary.TButton', command=self.recover_account, width=25); self.recover_button.grid(row=2, column=0, pady=(30, 10))
        ttk.Label(form, text="Note: This function currently verifies the email exists.\nActual password reset email sending requires setup.", justify=tk.CENTER, font=('Segoe UI', 9)).grid(row=3, column=0, pady=(20, 0))

    def create_dashboard(self):
        self.dashboard_frame = ttk.Frame(self.root, style='TFrame', name='dashboard_frame'); self.dashboard_frame.columnconfigure(0, weight=1); self.dashboard_frame.rowconfigure(2, weight=1)
        header = ttk.Frame(self.dashboard_frame, style='Header.TFrame'); header.grid(row=0, column=0, pady=(20, 10), sticky="ew", padx=10); header.columnconfigure(1, weight=1)
        self.welcome_label = ttk.Label(header, text="🔐 Your Passwords", style='Title.TLabel'); self.welcome_label.grid(row=0, column=0, sticky='w')
        profile_button = ttk.Button(header, text="Edit Profile", style='Secondary.TButton', command=lambda: self.show_form("edit_profile")); profile_button.grid(row=0, column=2, sticky="e", padx=5)
        logout_button = ttk.Button(header, text="Log Out", style='Danger.TButton', command=self.logout); logout_button.grid(row=0, column=3, sticky="e", padx=5)
        toolbar = ttk.Frame(self.dashboard_frame, style='Form.TFrame'); toolbar.grid(row=1, column=0, pady=10, sticky="ew", padx=10); toolbar.columnconfigure(0, weight=1)
        self.search_entry_var = tk.StringVar(); self.search_entry = ttk.Entry(toolbar, textvariable=self.search_entry_var, width=50); self.search_entry.grid(row=0, column=0, padx=(0, 5), sticky="ew")
        self.search_entry.bind("<KeyRelease>", lambda e: self.search_passwords())
        search_button = ttk.Button(toolbar, text="🔍 Search", style='Secondary.TButton', command=self.search_passwords); search_button.grid(row=0, column=1, padx=5)
        clear_button = ttk.Button(toolbar, text="Clear", style='TButton', command=self.clear_search); clear_button.grid(row=0, column=2, padx=5)
        tree_frame = ttk.Frame(self.dashboard_frame, style='TFrame'); tree_frame.grid(row=2, column=0, sticky="nsew", padx=10); tree_frame.columnconfigure(0, weight=1); tree_frame.rowconfigure(0, weight=1)
        self.tree = ttk.Treeview(tree_frame, columns=('ID', 'Website/App', 'Username', 'Email'), show='headings', style='Treeview')
        self.tree.heading('ID', text='ID'); self.tree.heading('Website/App', text='Website/App'); self.tree.heading('Username', text='Username'); self.tree.heading('Email', text='Email')
        self.tree.column('ID', width=0, stretch=tk.NO); self.tree.column('Website/App', width=250, anchor='w'); self.tree.column('Username', width=200, anchor='w'); self.tree.column('Email', width=300, anchor='w')
        self.tree.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview, style='Vertical.TScrollbar'); scrollbar.grid(row=0, column=1, sticky="ns"); self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.bind("<Double-1>", lambda e: self.edit_selected_password())
        buttons_frame = ttk.Frame(self.dashboard_frame, style='Form.TFrame'); buttons_frame.grid(row=3, column=0, pady=(15, 10), sticky="ew", padx=10); buttons_frame.columnconfigure(0, weight=1); buttons_frame.columnconfigure(1, weight=1); buttons_frame.columnconfigure(2, weight=1)
        add_button = ttk.Button(buttons_frame, text="➕ Add New", style='Primary.TButton', command=lambda: self.show_form("add_password")); add_button.grid(row=0, column=0, padx=10, sticky='e')
        self.dashboard_edit_button = ttk.Button(buttons_frame, text="✏️ Edit Selected", style='Secondary.TButton', command=self.edit_selected_password); self.dashboard_edit_button.grid(row=0, column=1, padx=10, sticky='ew')
        self.dashboard_delete_button = ttk.Button(buttons_frame, text="🗑️ Delete Selected", style='Danger.TButton', command=self.delete_password); self.dashboard_delete_button.grid(row=0, column=2, padx=10, sticky='w')

    def create_edit_profile_form(self):
        self.edit_profile_frame = ttk.Frame(self.root, style='TFrame', name='edit_profile_frame'); self.edit_profile_frame.columnconfigure(0, weight=1)
        header = ttk.Frame(self.edit_profile_frame, style='Header.TFrame'); header.grid(row=0, column=0, pady=(40, 20), sticky="ew"); header.columnconfigure(0, weight=1)
        ttk.Label(header, text="⚙️ Edit Your Profile", style='Title.TLabel').grid(row=0, column=0, sticky='w', padx=20)
        ttk.Button(header, text="← Back to Dashboard", style='Secondary.TButton', command=self.go_back).grid(row=0, column=1, sticky="e", padx=20)
        form = ttk.Frame(self.edit_profile_frame, style='Form.TFrame', width=450); form.grid(row=1, column=0, padx=20, pady=10, sticky="n"); form.columnconfigure(0, weight=1)
        ttk.Label(form, text="Name").grid(row=0, column=0, columnspan=2, sticky="w", pady=(10, 2))
        self.edit_username_var = tk.StringVar(); self.edit_username = ttk.Entry(form, textvariable=self.edit_username_var, width=50); self.edit_username.grid(row=1, column=0, columnspan=2, sticky="ew", pady=5)
        ttk.Label(form, text="New Password (leave blank to keep current)").grid(row=2, column=0, columnspan=2, sticky="w", pady=(10, 2))
        self.edit_password_var = tk.StringVar(); self.edit_password = ttk.Entry(form, textvariable=self.edit_password_var, show="•", width=50); self.edit_password.grid(row=3, column=0, sticky="ew", pady=5)
        self.edit_show_password_var = tk.BooleanVar(value=False); self.edit_show_password = ttk.Checkbutton(form, text="Show", variable=self.edit_show_password_var, command=lambda: self.toggle_password(self.edit_password, self.edit_show_password_var)); self.edit_show_password.grid(row=3, column=1, padx=(10,0), sticky='w')
        ttk.Label(form, text="Recovery Email").grid(row=4, column=0, columnspan=2, sticky="w", pady=(10, 2))
        self.edit_recovery_email_var = tk.StringVar(); self.edit_recovery_email = ttk.Entry(form, textvariable=self.edit_recovery_email_var, width=50); self.edit_recovery_email.grid(row=5, column=0, columnspan=2, sticky="ew", pady=5); self.edit_recovery_email.bind("<KeyRelease>", lambda e: self.validate_field(self.edit_recovery_email_var, self.edit_recovery_email, 'email'))
        ttk.Label(form, text="New PIN (4 digits, optional, blank to keep/remove)").grid(row=6, column=0, sticky="w", pady=(10, 2))
        self.edit_pin_var = tk.StringVar(); validate_pin_cmd = self.root.register(lambda P: P.isdigit() and len(P) <= 4 or P == ""); self.edit_pin = ttk.Entry(form, textvariable=self.edit_pin_var, show="•", width=10, validate='key', validatecommand=(validate_pin_cmd, '%P'))
        self.edit_pin.grid(row=7, column=0, sticky="w", pady=5); self.edit_show_pin_var = tk.BooleanVar(value=False); self.edit_show_pin = ttk.Checkbutton(form, text="Show", variable=self.edit_show_pin_var, command=lambda: self.toggle_password(self.edit_pin, self.edit_show_pin_var)); self.edit_show_pin.grid(row=7, column=1, padx=(10,0), sticky='w')
        buttons_frame = ttk.Frame(form, style='Form.TFrame'); buttons_frame.grid(row=8, column=0, columnspan=2, pady=(30, 10), sticky='ew'); buttons_frame.columnconfigure(0, weight=1)
        self.save_profile_button = ttk.Button(buttons_frame, text="Save Profile Changes", style='Primary.TButton', command=self.save_profile_changes); self.save_profile_button.grid(row=0, column=0, columnspan=2, padx=5, sticky='ew')

    def create_add_password_form(self):
        self.add_password_frame = ttk.Frame(self.root, style='TFrame', name='add_password_frame'); self.add_password_frame.columnconfigure(0, weight=1)
        header = ttk.Frame(self.add_password_frame, style='Header.TFrame'); header.grid(row=0, column=0, pady=(40, 20), sticky="ew"); header.columnconfigure(0, weight=1)
        ttk.Label(header, text="➕ Add New Password Entry", style='Title.TLabel').grid(row=0, column=0, sticky='w', padx=20)
        ttk.Button(header, text="← Back to Dashboard", style='Secondary.TButton', command=self.go_back).grid(row=0, column=1, sticky="e", padx=20)
        form = ttk.Frame(self.add_password_frame, style='Form.TFrame', width=450); form.grid(row=1, column=0, padx=20, pady=10, sticky="n"); form.columnconfigure(0, weight=1)
        ttk.Label(form, text="Website or Application Name").grid(row=0, column=0, columnspan=2, sticky="w", pady=(10, 2))
        self.add_app_name_var = tk.StringVar(); self.add_app_name = ttk.Entry(form, textvariable=self.add_app_name_var, width=50); self.add_app_name.grid(row=1, column=0, columnspan=2, sticky="ew", pady=5); self.add_app_name.bind("<Return>", lambda e: self.add_username.focus_set())
        ttk.Label(form, text="Username / Login ID").grid(row=2, column=0, columnspan=2, sticky="w", pady=(10, 2))
        self.add_username_var = tk.StringVar(); self.add_username = ttk.Entry(form, textvariable=self.add_username_var, width=50); self.add_username.grid(row=3, column=0, columnspan=2, sticky="ew", pady=5); self.add_username.bind("<Return>", lambda e: self.add_password.focus_set())
        ttk.Label(form, text="Password").grid(row=4, column=0, columnspan=2, sticky="w", pady=(10, 2))
        self.add_password_var = tk.StringVar(); self.add_password = ttk.Entry(form, textvariable=self.add_password_var, show="•", width=50); self.add_password.grid(row=5, column=0, sticky="ew", pady=5)
        self.add_show_password_var = tk.BooleanVar(value=False); self.add_show_password = ttk.Checkbutton(form, text="Show", variable=self.add_show_password_var, command=lambda: self.toggle_password(self.add_password, self.add_show_password_var)); self.add_show_password.grid(row=5, column=1, padx=(10,0), sticky='w')
        self.add_password.bind("<Return>", lambda e: self.add_email.focus_set())
        ttk.Label(form, text="Associated Email (Optional)").grid(row=6, column=0, columnspan=2, sticky="w", pady=(10, 2))
        self.add_email_var = tk.StringVar(); self.add_email = ttk.Entry(form, textvariable=self.add_email_var, width=50); self.add_email.grid(row=7, column=0, columnspan=2, sticky="ew", pady=5); self.add_email.bind("<KeyRelease>", lambda e: self.validate_field(self.add_email_var, self.add_email, 'email_optional')); self.add_email.bind("<Return>", lambda e: self.save_new_password())
        self.save_password_button = ttk.Button(form, text="Save New Password", style='Primary.TButton', command=self.save_new_password, width=20); self.save_password_button.grid(row=8, column=0, columnspan=2, pady=(30, 10))

    def create_edit_password_form(self):
        self.edit_password_frame = ttk.Frame(self.root, style='TFrame', name='edit_password_frame'); self.edit_password_frame.columnconfigure(0, weight=1)
        header = ttk.Frame(self.edit_password_frame, style='Header.TFrame'); header.grid(row=0, column=0, pady=(40, 20), sticky="ew"); header.columnconfigure(0, weight=1)
        ttk.Label(header, text="✏️ Edit Password Entry", style='Title.TLabel').grid(row=0, column=0, sticky='w', padx=20)
        ttk.Button(header, text="← Back to Dashboard", style='Secondary.TButton', command=self.go_back).grid(row=0, column=1, sticky="e", padx=20)
        form = ttk.Frame(self.edit_password_frame, style='Form.TFrame', width=450); form.grid(row=1, column=0, padx=20, pady=10, sticky="n"); form.columnconfigure(0, weight=1)
        ttk.Label(form, text="Website or Application Name").grid(row=0, column=0, columnspan=2, sticky="w", pady=(10, 2))
        self.edit_app_name_var = tk.StringVar(); self.edit_app_name = ttk.Entry(form, textvariable=self.edit_app_name_var, width=50); self.edit_app_name.grid(row=1, column=0, columnspan=2, sticky="ew", pady=5); self.edit_app_name.bind("<Return>", lambda e: self.edit_password_username.focus_set())
        ttk.Label(form, text="Username / Login ID").grid(row=2, column=0, columnspan=2, sticky="w", pady=(10, 2))
        self.edit_password_username_var = tk.StringVar(); self.edit_password_username = ttk.Entry(form, textvariable=self.edit_password_username_var, width=50); self.edit_password_username.grid(row=3, column=0, columnspan=2, sticky="ew", pady=5); self.edit_password_username.bind("<Return>", lambda e: self.edit_password_password.focus_set())
        ttk.Label(form, text="Password").grid(row=4, column=0, columnspan=2, sticky="w", pady=(10, 2))
        self.edit_password_password_var = tk.StringVar(); self.edit_password_password = ttk.Entry(form, textvariable=self.edit_password_password_var, show="•", width=50); self.edit_password_password.grid(row=5, column=0, sticky="ew", pady=5)
        self.edit_password_show_var = tk.BooleanVar(value=False); self.edit_show_password_check = ttk.Checkbutton(form, text="Show", variable=self.edit_password_show_var, command=lambda: self.toggle_password(self.edit_password_password, self.edit_password_show_var)); self.edit_show_password_check.grid(row=5, column=1, padx=(10,0), sticky='w')
        self.edit_password_password.bind("<Return>", lambda e: self.edit_password_email.focus_set())
        ttk.Label(form, text="Associated Email (Optional)").grid(row=6, column=0, columnspan=2, sticky="w", pady=(10, 2))
        self.edit_password_email_var = tk.StringVar(); self.edit_password_email = ttk.Entry(form, textvariable=self.edit_password_email_var, width=50); self.edit_password_email.grid(row=7, column=0, columnspan=2, sticky="ew", pady=5); self.edit_password_email.bind("<KeyRelease>", lambda e: self.validate_field(self.edit_password_email_var, self.edit_password_email, 'email_optional')); self.edit_password_email.bind("<Return>", lambda e: self.save_edited_password())
        self.save_edits_button = ttk.Button(form, text="Save Changes", style='Primary.TButton', command=self.save_edited_password, width=20); self.save_edits_button.grid(row=8, column=0, columnspan=2, pady=(30, 10))

    def toggle_password(self, entry_widget, show_var):
        if show_var.get(): entry_widget.configure(show="")
        else: entry_widget.configure(show="•")

    def validate_field(self, string_var, entry_widget, validation_type='email'):
        value = string_var.get().strip(); is_valid = False
        if not value: entry_widget.configure(style='TEntry'); return True
        if validation_type == 'email': is_valid = self.validate_email(value)
        elif validation_type == 'email_optional': is_valid = self.validate_email(value) if value else True
        elif validation_type == 'non_empty': is_valid = bool(value)
        if is_valid: entry_widget.configure(style='TEntry')
        else: entry_widget.configure(style='Error.TEntry')
        return is_valid

    def validate_password_strength(self):
        password = self.register_password_var.get(); strength = 0; label = "Strength: -"; color = self.text_color
        criteria_met = sum([len(password) >= 8, bool(re.search(r'[0-9]', password)), bool(re.search(r'[A-Z]', password)), bool(re.search(r'[a-z]', password)), bool(re.search(r'[!@#$%^&*()_+=[\]{};\'\\:"|,./<>?~`-]', password))])
        if len(password) == 0: strength = 0; label = "Strength: -"
        elif criteria_met <= 2: strength = max(25, len(password) * 5); label = "Strength: Weak"; color = self.error_color; self.style.configure('Weak.Horizontal.TProgressbar', background=self.error_color); self.password_strength_bar.configure(style='Weak.Horizontal.TProgressbar')
        elif criteria_met <= 4 : strength = 65; label = "Strength: Medium"; color = self.warning_color; self.style.configure('Medium.Horizontal.TProgressbar', background=self.warning_color); self.password_strength_bar.configure(style='Medium.Horizontal.TProgressbar')
        else: strength = 100; label = "Strength: Strong"; color = self.success_color; self.style.configure('Strong.Horizontal.TProgressbar', background=self.success_color); self.password_strength_bar.configure(style='Strong.Horizontal.TProgressbar')
        self.password_strength_bar['value'] = strength; self.password_strength_label.configure(text=label, foreground=color)

    def validate_email(self, email):
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'; return re.match(pattern, email) is not None

    def show_loading(self, button, operation, original_text):
        if self.is_loading: return
        # Allow auth operations even if DB init failed, but not others
        if not self.firebase_service.db and operation.__name__ not in ['perform_login', 'perform_register', 'perform_recovery']:
            messagebox.showerror("Database Error", "Firebase is not connected. Operation cannot be performed."); return
        self.is_loading = True; button.configure(state='disabled', text="Processing..."); self.root.config(cursor="wait"); self.root.update_idletasks()
        try: operation()
        finally: self.root.config(cursor=""); button.configure(state='normal', text=original_text); self.is_loading = False

    def login(self):
        email = self.login_email_var.get().strip()
        plain_master_password = self.login_password_var.get().strip()

        if not self.validate_field(self.login_email_var, self.login_email, 'email'):
            messagebox.showerror("Login Error", "Invalid email."); self.login_email.focus_set(); return
        if not plain_master_password:
            messagebox.showerror("Login Error", "Password empty."); self.login_password.focus_set(); return
        if not self.firebase_service.db: # Check if Firebase service itself is available
             messagebox.showerror("Login Error", "Database service is not available. Cannot log in.")
             return

        def perform_login():
            user_doc = self.firebase_service.get_user_by_email(email)

            if user_doc and check_hashed_value(plain_master_password, user_doc.get('password')):
                self.current_user = {
                    'id': user_doc['id'], 'name': user_doc['name'], 'email': user_doc['email'],
                    'key_salt': user_doc.get('key_salt'), 'recovery_email': user_doc.get('recovery_email'),
                    'pin_hash': user_doc.get('pin')
                }
                try:
                    if not self.current_user['key_salt']: # Should not happen for new users
                        messagebox.showerror("Login Error", "User account data is incomplete (missing salt). Cannot proceed.")
                        self.current_user = None; return
                    derived_key = derive_encryption_key(plain_master_password, self.current_user['key_salt'])
                    self.encryption_service = EncryptionService(derived_key)
                except Exception as e:
                    messagebox.showerror("Encryption Key Error", f"Could not prepare data encryption: {e}")
                    self.current_user = None; self.encryption_service = None; return

                self.update_welcome_message()
                self.show_form("dashboard")
                self.login_email_var.set(""); self.login_password_var.set("")
                self.login_show_password_var.set(False); self.toggle_password(self.login_password, self.login_show_password_var)
                messagebox.showinfo("Login Success", f"Welcome, {self.current_user['name']}!")
            else:
                messagebox.showerror("Login Failed", "Invalid email or password.")
        self.show_loading(self.login_button, perform_login, "Login")

    def register(self):
        name = self.register_name_var.get().strip()
        email = self.register_email_var.get().strip()
        plain_password = self.register_password_var.get().strip()
        plain_pin = self.register_pin_var.get().strip()

        if not self.validate_field(self.register_name_var, self.register_name, 'non_empty'):
             messagebox.showerror("Reg Error", "Name empty."); self.register_name.focus_set(); return
        if not self.validate_field(self.register_email_var, self.register_email, 'email'):
             messagebox.showerror("Reg Error", "Invalid email."); self.register_email.focus_set(); return
        if len(plain_password) < 8:
             messagebox.showerror("Reg Error", "Password too short."); self.register_password.focus_set(); return
        if plain_pin and (not plain_pin.isdigit() or len(plain_pin) != 4):
            messagebox.showerror("Reg Error", "PIN must be 4 digits if provided."); self.register_pin.focus_set(); return
        if not self.firebase_service.db:
             messagebox.showerror("Reg Error", "Database service unavailable. Cannot register."); return

        def perform_register():
            user_id_or_error = self.firebase_service.create_user(name, email, plain_password, email, plain_pin if plain_pin else None)
            if user_id_or_error == "exists":
                messagebox.showerror("Reg Failed", "Email already exists."); self.register_email.focus_set()
            elif user_id_or_error:
                messagebox.showinfo("Reg Successful", "Account created! Please log in.")
                self.register_name_var.set(""); self.register_email_var.set(""); self.register_password_var.set(""); self.register_pin_var.set("")
                self.register_show_password_var.set(False); self.toggle_password(self.register_password, self.register_show_password_var)
                self.register_show_pin_var.set(False); self.toggle_password(self.register_pin, self.register_show_pin_var)
                self.validate_password_strength(); self.show_form("login")
            else:
                messagebox.showerror("Reg Failed", "Could not create account (database error).")
        self.show_loading(self.register_button, perform_register, "Register")

    def recover_account(self):
        email_rec = self.recovery_email_var.get().strip() # Renamed variable to avoid conflict
        if not self.validate_field(self.recovery_email_var, self.recovery_email, 'email'):
            messagebox.showerror("Recovery Error", "Invalid email format."); self.recovery_email.focus_set(); return
        if not self.firebase_service.db:
             messagebox.showerror("Recovery Error", "Database service unavailable."); return
        def perform_recovery():
            user = self.firebase_service.get_user_by_email_or_recovery(email_rec)
            if user: print(f"SIMULATING: Sending recovery instructions to {user.get('email') or email_rec}")
            messagebox.showinfo("Recovery Initiated", f"If an account exists for {email_rec}, recovery instructions have been 'sent'.")
            self.show_form("login"); self.recovery_email_var.set("")
        self.show_loading(self.recover_button, perform_recovery, "Send Recovery Instructions")

    def logout(self, silent=False):
        confirm = True
        if not silent: confirm = messagebox.askyesno("Log Out", "Are you sure you want to log out?")
        if confirm:
            self.current_user = None; self.encryption_service = None; self.editing_password = None
            for item in self.tree.get_children(): self.tree.delete(item)
            if hasattr(self, 'tree') and self.tree.winfo_exists(): # Check if tree exists
                 if not self.tree.exists("INFO_LOGGED_OUT"): # Avoid duplicate messages if already handled by show_form
                    self.tree.insert('', tk.END, iid="INFO_LOGGED_OUT", values=("", "Logged out. Please log in again.", "", ""), tags=("info_row",))
            self.search_entry_var.set(""); self.form_history = []
            self.show_form("login")
            if not silent: messagebox.showinfo("Logged Out", "You have been successfully logged out.")

    def update_welcome_message(self):
        if self.current_user and hasattr(self, 'welcome_label'): self.welcome_label.config(text=f"🔐 Welcome, {self.current_user.get('name', 'User')}!")
        elif hasattr(self, 'welcome_label'): self.welcome_label.config(text="🔐 Your Passwords")

    def clear_search(self): self.search_entry_var.set(""); self.refresh_password_list()
    def search_passwords(self): self.refresh_password_list(search_term=self.search_entry_var.get().strip().lower())

    def refresh_password_list(self, search_term=None):
        # Clear existing items from the treeview
        for item in self.tree.get_children():
            self.tree.delete(item)

        # Helper to insert info messages into tree
        def _insert_info_message(iid, message, tag="info_row"):
            if not self.tree.exists(iid):
                self.tree.insert('', tk.END, iid=iid, values=("", message, "", ""), tags=(tag,))

        if not self.firebase_service.db:
            _insert_info_message("INFO_NO_DB_CONN", "Database not connected. Cannot load passwords.", "info_row_error")
            return
        if not self.current_user:
            _insert_info_message("INFO_NO_LOGIN_REFRESH", "Not logged in. Cannot load passwords.")
            return
        if not self.encryption_service:
            messagebox.showwarning("Data Access Error", "Encryption service not ready. Cannot load passwords. Please log out and log back in.")
            _insert_info_message("INFO_NO_ENCRYPTION_SVC", "Encryption service not ready.", "info_row_error")
            return

        user_id = self.current_user.get('id')
        if not user_id:
            messagebox.showerror("Error", "User ID missing. Cannot load passwords.")
            _insert_info_message("INFO_NO_USER_ID_REFRESH", "User ID missing. Cannot load passwords.", "info_row_error")
            return

        try:
            passwords_data = self.firebase_service.get_passwords_for_user(user_id, self.encryption_service, search_term)

            if passwords_data:
                for pwd_doc in passwords_data:
                    doc_id = pwd_doc.get('id')
                    if not doc_id:
                        print(f"Warning: Password entry missing 'id' in retrieved data: {pwd_doc}")
                        continue # Skip entries without an ID

                    app_name = pwd_doc.get('app', 'N/A')
                    app_name_display = app_name
                    
                    # Check for decryption error marker
                    if 'password' in pwd_doc and pwd_doc['password'] == "DECRYPTION_ERROR":
                        app_name_display = f"{app_name} (DECRYPTION FAILED)"
                    
                    username = pwd_doc.get('username', 'N/A')
                    email = pwd_doc.get('email', '') # Default to empty string if missing

                    self.tree.insert('', tk.END, iid=doc_id,
                                     values=(doc_id, app_name_display, username, email))
            else: # passwords_data is None or empty list
                empty_message = "No passwords found."
                if search_term:
                    empty_message = f"No passwords match '{search_term}'."
                _insert_info_message("INFO_EMPTY_LIST", empty_message)

        except InvalidToken: # This implies a broader decryption issue not caught per-item by FirebaseService
            messagebox.showerror("Critical Decryption Error", 
                                 "A critical decryption error occurred. This might be due to a master password change or data corruption. "
                                 "Please log out and log back in. If the problem persists, some data may be unrecoverable.")
            _insert_info_message("INFO_CRITICAL_DECRYPT_FAIL", "Critical decryption error. Data unreadable.", "info_row_error")
        except Exception as e:
            error_type = type(e).__name__
            print(f"Error refreshing password list: {error_type}: {e}") # Log to console
            messagebox.showerror("List Error", f"An error occurred while displaying passwords: {error_type}")
            _insert_info_message("INFO_LIST_GENERIC_ERROR", f"Error displaying list: {error_type}", "info_row_error")


    def load_profile_data(self):
         if not self.current_user or not self.firebase_service.db:
             messagebox.showerror("Error", "Not logged in or database unavailable."); self.go_back(); return
         profile_data = self.firebase_service.get_user_by_id(self.current_user['id'])
         if profile_data:
             self.edit_username_var.set(profile_data.get('name', ''))
             self.edit_recovery_email_var.set(profile_data.get('recovery_email', self.current_user.get('email', '')))
             self.edit_pin_var.set("")
             self.edit_password_var.set("")
             self.edit_show_password_var.set(False); self.toggle_password(self.edit_password, self.edit_show_password_var)
             self.edit_show_pin_var.set(False); self.toggle_password(self.edit_pin, self.edit_show_pin_var)
         else:
             messagebox.showerror("Error", "Could not load profile data from Firebase."); self.go_back()

    def save_profile_changes(self):
        if not self.current_user or not self.firebase_service.db:
             messagebox.showerror("Error", "Not logged in or database unavailable."); return
        new_name = self.edit_username_var.get().strip()
        new_plain_password = self.edit_password_var.get()
        new_recovery_email = self.edit_recovery_email_var.get().strip()
        new_plain_pin = self.edit_pin_var.get().strip()

        if not new_name: messagebox.showerror("Validation Error", "Name cannot be empty."); self.edit_username.focus_set(); return
        if new_recovery_email and not self.validate_email(new_recovery_email):
            messagebox.showerror("Validation Error", "Invalid format for Recovery Email."); self.edit_recovery_email.focus_set(); return
        if new_plain_pin and (not new_plain_pin.isdigit() or len(new_plain_pin) != 4):
            messagebox.showerror("Validation Error", "PIN must be exactly 4 digits."); self.edit_pin.focus_set(); return
        if new_plain_password and len(new_plain_password) < 8:
            messagebox.showerror("Validation Error", "New password must be at least 8 characters."); self.edit_password.focus_set(); return

        def perform_save():
            updates = {}
            db_user_data = self.firebase_service.get_user_by_id(self.current_user['id'])
            if not db_user_data: messagebox.showerror("Error", "Failed to fetch current profile for comparison."); return

            if new_name != db_user_data.get('name'): updates['name'] = new_name
            if new_plain_password: updates['password'] = new_plain_password # FirebaseService handles hashing
            if new_recovery_email and new_recovery_email != db_user_data.get('recovery_email'):
                updates['recovery_email'] = new_recovery_email
            if new_plain_pin: updates['pin'] = new_plain_pin # FirebaseService handles hashing
            elif not new_plain_pin and db_user_data.get('pin') is not None: updates['pin'] = None # Request to remove PIN

            if not updates: messagebox.showinfo("No Changes", "No changes were detected in your profile."); return
            success = self.firebase_service.update_user(self.current_user['id'], updates)
            if success:
                 messagebox.showinfo("Success", "Profile updated successfully.")
                 if 'name' in updates: self.current_user['name'] = updates['name'] 
                 if 'password' in updates:
                     messagebox.showwarning("Password Changed", "Your master password has changed. For the new password to be used for encrypting/decrypting password entries, please log out and log back in.")
                 self.update_welcome_message(); self.show_form("dashboard")
            else: messagebox.showerror("Error", "Failed to update profile in Firebase.")
        self.show_loading(self.save_profile_button, perform_save, "Save Profile Changes")

    def save_new_password(self):
        app = self.add_app_name_var.get().strip()
        username = self.add_username_var.get().strip()
        plain_password_val = self.add_password_var.get()
        email_val = self.add_email_var.get().strip()

        if not app: messagebox.showerror("Validation Error", "App name empty."); self.add_app_name.focus_set(); return
        if not username: messagebox.showerror("Validation Error", "Username empty."); self.add_username.focus_set(); return
        if not plain_password_val: messagebox.showerror("Validation Error", "Password empty."); self.add_password.focus_set(); return
        if email_val and not self.validate_email(email_val):
             messagebox.showerror("Validation Error", "Invalid Email."); self.add_email.focus_set(); return
        if not self.current_user or not self.encryption_service or not self.firebase_service.db:
             messagebox.showerror("Error", "Not logged in / Encryption service not ready / Database issue."); return

        def perform_save():
             new_id = self.firebase_service.add_password_entry(
                 self.current_user['id'], app, username, plain_password_val,
                 email_val if email_val else '', self.encryption_service
             )
             if new_id: # Assumes add_password_entry returns the ID of the new entry or a truthy value on success
                 self.refresh_password_list()
                 messagebox.showinfo("Success", f"Password entry for '{app}' added successfully.")
                 self.show_form("dashboard")
                 self.add_app_name_var.set(""); self.add_username_var.set(""); self.add_password_var.set(""); self.add_email_var.set("")
                 self.add_show_password_var.set(False); self.toggle_password(self.add_password, self.add_show_password_var)
             else: messagebox.showerror("Error", "Failed to save password to Firebase.")
        self.show_loading(self.save_password_button, perform_save, "Save New Password")

    def edit_selected_password(self):
        selected_items = self.tree.selection()
        if not selected_items: messagebox.showwarning("Selection Error", "Select an entry to edit."); return
        if len(selected_items) > 1: messagebox.showwarning("Selection Error", "Select only one entry."); return
        selected_iid = selected_items[0]
        
        # Avoid trying to edit info rows
        if selected_iid.startswith("INFO_"): return

        if not self.current_user or not self.encryption_service or not self.firebase_service.db:
             messagebox.showerror("Error", "Not logged in / Encryption service not ready / Database issue."); return

        def perform_load_for_edit():
            try:
                pwd_data = self.firebase_service.get_password_entry_by_id(
                    selected_iid, self.current_user['id'], self.encryption_service
                )
            except InvalidToken: # Specific error from service or direct decryption
                messagebox.showerror("Decryption Error", "Failed to load password for editing due to a decryption issue. The master password may have changed or data is corrupt.")
                self.refresh_password_list(); return
            except Exception as e:
                messagebox.showerror("Load Error", f"Failed to load password for editing: {e}")
                self.refresh_password_list(); return

            if pwd_data:
                if pwd_data.get('password') == "DECRYPTION_ERROR": # Check for per-item decryption error marker
                     messagebox.showerror("Decryption Error", "Cannot edit. The password data is unrecoverable with the current master key."); return
                self.editing_password = pwd_data
                self.edit_app_name_var.set(pwd_data.get('app',''))
                self.edit_password_username_var.set(pwd_data.get('username',''))
                self.edit_password_password_var.set(pwd_data.get('password','')) # This should be plain text if decryption succeeded
                self.edit_password_email_var.set(pwd_data.get('email',''))
                self.edit_password_show_var.set(False); self.toggle_password(self.edit_password_password, self.edit_password_show_var)
                self.show_form("edit_password"); self.edit_app_name.focus_set()
            else:
                messagebox.showerror("Error", "Could not retrieve password details for editing. It might have been deleted."); self.refresh_password_list()
        self.show_loading(self.dashboard_edit_button, perform_load_for_edit, "✏️ Edit Selected")

    def save_edited_password(self):
        if not self.editing_password or not self.current_user or not self.encryption_service or not self.firebase_service.db:
            messagebox.showerror("Error", "No entry selected/Not logged in/Enc. service not ready/DB issue."); self.show_form("dashboard"); return
        app = self.edit_app_name_var.get().strip()
        username = self.edit_password_username_var.get().strip()
        plain_password_val = self.edit_password_password_var.get()
        email_val = self.edit_password_email_var.get().strip()

        if not app: messagebox.showerror("Validation Error", "App name empty."); self.edit_app_name.focus_set(); return
        if not username: messagebox.showerror("Validation Error", "Username empty."); self.edit_password_username.focus_set(); return
        if not plain_password_val: messagebox.showerror("Validation Error", "Password empty."); self.edit_password_password.focus_set(); return
        if email_val and not self.validate_email(email_val):
             messagebox.showerror("Validation Error", "Invalid Email."); self.edit_password_email.focus_set(); return

        original = self.editing_password
        # Compare against potentially missing keys in original using .get()
        if (app == original.get('app','') and username == original.get('username','') and \
            plain_password_val == original.get('password','') and email_val == original.get('email','')):
            messagebox.showinfo("No Changes", "No changes detected for this password entry."); self.show_form("dashboard"); return

        def perform_save_edit():
            update_data = {'app': app, 'username': username, 'password': plain_password_val, 'email': email_val if email_val else ''}
            success = self.firebase_service.update_password_entry(
                self.editing_password['id'], self.current_user['id'], update_data, self.encryption_service
            )
            if success:
                 self.refresh_password_list(); messagebox.showinfo("Success", f"Password entry for '{app}' updated successfully.")
                 self.show_form("dashboard"); self.editing_password = None
            else: messagebox.showerror("Error", "Failed to update password in Firebase.")
        self.show_loading(self.save_edits_button, perform_save_edit, "Save Changes")

    def delete_password(self):
        selected_items_iids = self.tree.selection()
        if not selected_items_iids: messagebox.showwarning("Selection Error", "Please select entry/entries to delete."); return
        
        # Filter out info rows
        actual_item_iids = [iid for iid in selected_items_iids if not iid.startswith("INFO_")]
        if not actual_item_iids: messagebox.showwarning("Selection Error", "No actual password entries selected for deletion."); return

        if not self.current_user or not self.firebase_service.db:
             messagebox.showerror("Error", "Not logged in or database unavailable."); return
        
        confirm_msg = f"Are you sure you want to permanently delete {len(actual_item_iids)} selected password entr{'y' if len(actual_item_iids) == 1 else 'ies'}?"
        if not messagebox.askyesno("Confirm Deletion", confirm_msg): return

        def perform_delete():
            deleted_count = 0; failed_ids = []
            for item_iid in actual_item_iids:
                success = self.firebase_service.delete_password_entry(item_iid, self.current_user['id'])
                if success: deleted_count += 1
                else: failed_ids.append(item_iid)
            
            if deleted_count > 0:
                msg = f"{deleted_count} password entr{'y' if deleted_count == 1 else 'ies'} deleted successfully."
                if failed_ids: msg += f"\nCould not delete {len(failed_ids)} entr{'y' if len(failed_ids) == 1 else 'ies'} (IDs: {', '.join(failed_ids[:3])}{'...' if len(failed_ids)>3 else ''})."
                messagebox.showinfo("Deletion Result", msg)
            elif failed_ids: messagebox.showerror("Deletion Failed", f"Could not delete the selected entr{'y' if len(failed_ids) == 1 else 'ies'}.")
            else: messagebox.showinfo("Deletion Info", "No password entries were deleted (they might have already been removed or no actual entries were selected).") # Should be covered by earlier check
            self.refresh_password_list()
        self.show_loading(self.dashboard_delete_button, perform_delete, "🗑️ Delete Selected")

# --- Main Execution ---
if __name__ == "__main__":
    try:
        root = tk.Tk()
        root.minsize(700, 500)
        app = PasswordManagerApp(root)
        root.mainloop()
    except Exception as e:
        import traceback
        error_msg = f"An unexpected fatal error occurred:\n{e}\n\n{traceback.format_exc()}"
        try: # Try to show messagebox if tkinter is still somewhat functional
            messagebox.showerror("Fatal Error", error_msg)
        except:
            pass # If tkinter itself is broken, just print
        print(f"FATAL ERROR: {e}")
        traceback.print_exc()
