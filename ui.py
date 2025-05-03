import tkinter as tk
from tkinter import messagebox, ttk
import re
import mysql.connector
from mysql.connector import Error
# It's highly recommended to use a proper password hashing library
# import bcrypt # Example: pip install bcrypt
import random # For PIN generation
import time # Potentially for delays, but not used in core logic currently

# --- Database Schema Assumption ---
# CREATE DATABASE IF NOT EXISTS password_manager;
# USE password_manager;
#
# CREATE TABLE IF NOT EXISTS users (
#     id INT AUTO_INCREMENT PRIMARY KEY,
#     name VARCHAR(255) NOT NULL,
#     email VARCHAR(255) NOT NULL UNIQUE,
#     password VARCHAR(255) NOT NULL, -- STORE HASHED PASSWORDS HERE, NOT PLAIN TEXT!
#     recovery_email VARCHAR(255),
#     pin VARCHAR(255) NULL, -- Store hashed/encrypted PIN or handle differently
#     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
# );
#
# CREATE TABLE IF NOT EXISTS passwords (
#     id INT AUTO_INCREMENT PRIMARY KEY,
#     user_id INT NOT NULL,
#     app VARCHAR(255) NOT NULL,
#     username VARCHAR(255) NOT NULL,
#     password VARCHAR(255) NOT NULL, -- STORE ENCRYPTED PASSWORDS HERE, NOT PLAIN TEXT!
#     email VARCHAR(255) NOT NULL,
#     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
#     updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
#     FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
# );
# --- End Database Schema Assumption ---

class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")
        # Increased initial size for better layout visibility
        self.root.geometry("950x700")
        self.root.configure(bg="#e8ecef")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        # --- IMPORTANT SECURITY NOTE ---
        # Hardcoding credentials is bad practice for production. Use environment variables or config files.
        # Storing passwords (user account and saved passwords) in plain text is extremely insecure.
        # Use strong hashing (e.g., bcrypt, Argon2) for user passwords and encryption for stored passwords.
        # This example focuses on GUI structure and basic DB interaction, NOT secure practices.
        # --- END SECURITY NOTE ---

        self.db_config = {
            'host': 'localhost',
            'user': 'root',            # Replace with your DB username
            'password': 'password', # Replace with your DB password
            'database': 'password_manager' # Replace with your DB name
        }
        self.conn = None
        self.connect_to_db() # Attempt connection on startup

        # Theme colors (WCAG-compliant examples)
        self.primary_color = "#2c5282"  # Dark blue
        self.secondary_color = "#3182ce"  # Lighter blue
        self.accent_color = "#90cdf4"  # Soft blue
        self.bg_color = "#e8ecef"      # Light gray background
        self.text_color = "#1a202c"      # Dark gray text
        self.error_color = "#e53e3e"     # Red for errors
        self.success_color = "#38a169"    # Green for success
        self.warning_color = "#d69e2e"    # Amber for warnings (like medium password)
        self.entry_bg_color = "#ffffff"   # White entry background
        self.entry_fg_color = self.text_color # Default entry text color

        self.configure_styles()

        self.passwords = [] # This seems unused, data is fetched directly
        self.current_user = None # Dictionary holding logged-in user's data {id, name, email}
        self.editing_password = None # Dictionary holding password data being edited {id, app, username, password, email}
        self.form_history = [] # Stack to manage navigation history
        self.is_loading = False # Flag to prevent multiple simultaneous operations

        # Create all form frames (initialized but not packed)
        self.create_login_form()
        self.create_register_form()
        self.create_recovery_form()
        self.create_dashboard()
        self.create_edit_profile_form()
        self.create_add_password_form()
        self.create_edit_password_form()

        # Show the initial form
        self.show_form("login")

    def configure_styles(self):
        """Configures the ttk styles for the application."""
        self.style = ttk.Style()
        self.style.theme_use('clam') # 'clam', 'alt', 'default', 'classic'

        # --- General Widget Styles ---
        self.style.configure('TFrame', background=self.bg_color)
        self.style.configure('TLabel', background=self.bg_color, foreground=self.text_color, font=('Segoe UI', 11))
        self.style.configure('Title.TLabel', font=('Segoe UI', 20, 'bold'), foreground=self.primary_color, padding=(0, 10, 0, 10)) # Added padding
        self.style.configure('Header.TFrame', background=self.bg_color) # Frame for headers
        self.style.configure('Form.TFrame', background=self.bg_color)   # Frame for form elements

        # --- Button Styles ---
        self.style.configure('TButton', font=('Segoe UI', 11, 'bold'), borderwidth=0, padding=10, relief='flat', anchor='center')
        self.style.map('TButton', foreground=[('!active', self.text_color), ('active', self.text_color)], background=[('!active', self.accent_color), ('active', self.secondary_color)]) # Default subtle button

        self.style.configure('Primary.TButton', background=self.primary_color, foreground='white')
        self.style.map('Primary.TButton', background=[('active', self.secondary_color)])

        self.style.configure('Secondary.TButton', background=self.secondary_color, foreground='white')
        self.style.map('Secondary.TButton', background=[('active', self.primary_color)]) # Slightly darker on hover

        self.style.configure('Danger.TButton', background=self.error_color, foreground='white')
        self.style.map('Danger.TButton', background=[('active', '#c53030')]) # Darker red

        # --- Entry Styles ---
        self.style.configure('TEntry',
                             fieldbackground=self.entry_bg_color,
                             foreground=self.entry_fg_color,
                             padding=8,
                             relief='flat', # Flat look
                             borderwidth=1, # Subtle border
                             bordercolor=self.secondary_color)
        self.style.map('TEntry',
                       bordercolor=[('focus', self.primary_color)], # Border color on focus
                       lightcolor=[('focus', self.primary_color)]) # Ensure focus ring matches


        self.style.configure('Error.TEntry', foreground=self.error_color, fieldbackground='#fee2e2') # Light red background for error

        # --- Checkbutton Style ---
        self.style.configure('TCheckbutton', background=self.bg_color, foreground=self.text_color, font=('Segoe UI', 10))
        self.style.map('TCheckbutton',
                       indicatorcolor=[('selected', self.primary_color), ('!selected', self.entry_bg_color)],
                       foreground=[('active', self.primary_color)])


        # --- Treeview Styles ---
        self.style.configure('Treeview',
                             background=self.entry_bg_color,
                             fieldbackground=self.entry_bg_color, # Background of the list area
                             foreground=self.text_color,
                             font=('Segoe UI', 10),
                             rowheight=30) # Increased row height
        self.style.configure('Treeview.Heading',
                             background=self.primary_color,
                             foreground='white',
                             font=('Segoe UI', 11, 'bold'),
                             padding=(10, 5), # Padding within heading cells
                             relief='flat')
        self.style.map('Treeview.Heading', relief=[('active','groove')]) # Subtle effect on hover/click
        self.style.map('Treeview',
                       background=[('selected', self.secondary_color)], # Selection color
                       foreground=[('selected', 'white')]) # Selection text color

        # --- Scrollbar Style ---
        self.style.configure('Vertical.TScrollbar', background=self.primary_color, troughcolor=self.bg_color, bordercolor=self.primary_color, arrowcolor='white')
        self.style.map('Vertical.TScrollbar', background=[('active', self.secondary_color)])


    def connect_to_db(self):
        """Establishes connection to the MySQL database."""
        # Close existing connection if open
        self.close_db()
        try:
            self.conn = mysql.connector.connect(**self.db_config)
            if self.conn.is_connected():
                print("Successfully connected to MySQL database")
                # Ensure database and tables exist (optional, good for setup)
                self.initialize_database()
        except Error as e:
            messagebox.showerror("Database Connection Error", f"Error connecting to MySQL database: {e}\nPlease ensure MySQL is running and configuration is correct.")
            # Optionally quit or disable DB features
            self.root.quit() # Exit if DB connection fails critically on startup

    def initialize_database(self):
        """Creates database and tables if they don't exist. (Basic example)"""
        try:
            cursor = self.conn.cursor()
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS {self.db_config['database']}")
            cursor.execute(f"USE {self.db_config['database']}")
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    name VARCHAR(255) NOT NULL,
                    email VARCHAR(255) NOT NULL UNIQUE,
                    password VARCHAR(255) NOT NULL,
                    recovery_email VARCHAR(255),
                    pin VARCHAR(255) NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS passwords (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    app VARCHAR(255) NOT NULL,
                    username VARCHAR(255) NOT NULL,
                    password VARCHAR(255) NOT NULL,
                    email VARCHAR(255) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
            """)
            self.conn.commit()
            cursor.close()
            print("Database and tables checked/initialized.")
        except Error as e:
            messagebox.showerror("Database Initialization Error", f"Error initializing database schema: {e}")


    def close_db(self):
        """Closes the database connection if it is open."""
        if hasattr(self, 'conn') and self.conn is not None and self.conn.is_connected():
            try:
                self.conn.close()
                print("Database connection closed")
            except mysql.connector.Error as e:
                print(f"Error closing database connection: {e}")
            finally:
                self.conn = None

    def on_closing(self):
        """Handles the window close event."""
        if messagebox.askokcancel("Quit", "Do you want to quit Password Manager?"):
            self.close_db()
            self.root.destroy()

    def show_form(self, form_name):
        """Hides all frames and shows the specified frame."""
        valid_forms = ["login", "register", "recover", "dashboard", "edit_profile", "add_password", "edit_password"]
        if form_name not in valid_forms:
            print(f"Error: Attempted to show invalid form '{form_name}'")
            return

        # Prevent adding the same form consecutively to history (e.g., on refresh)
        if not self.form_history or self.form_history[-1] != form_name:
             self.form_history.append(form_name)

        # Hide all frames first
        for frame in [self.login_frame, self.register_frame, self.recover_frame, self.dashboard_frame,
                      self.edit_profile_frame, self.add_password_frame, self.edit_password_frame]:
             if hasattr(self, frame.winfo_name()): # Check if frame exists before packing
                frame.pack_forget()

        # Show the requested frame
        target_frame = getattr(self, f"{form_name}_frame")
        target_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Special actions when showing specific forms
        if form_name == "dashboard":
            self.refresh_password_list() # Refresh data when showing dashboard
            # Set focus to search entry for convenience
            self.search_entry.focus_set()
        elif form_name == "edit_profile":
            self.load_profile_data() # Load current data into edit profile form
            self.edit_username.focus_set()
        elif form_name == "add_password":
            self.add_app_name.focus_set()


    def go_back(self):
        """Navigates to the previous form in the history."""
        if len(self.form_history) > 1:
            self.form_history.pop() # Remove current form
            previous_form = self.form_history[-1] # Get the one before that
            # Need to pop again because show_form will re-add it
            self.form_history.pop()
            self.show_form(previous_form)
        elif len(self.form_history) == 1 and self.form_history[0] != "login":
            # If only one item left and it's not login, go to login
             self.form_history.pop()
             self.show_form("login")

    # --- Form Creation Methods ---

    def create_login_form(self):
        self.login_frame = ttk.Frame(self.root, style='TFrame', name='login_frame')
        self.login_frame.columnconfigure(0, weight=1) # Center content horizontally

        # --- Header ---
        header = ttk.Frame(self.login_frame, style='Header.TFrame')
        header.grid(row=0, column=0, pady=(40, 20), sticky="ew")
        header.columnconfigure(0, weight=1) # Center label
        ttk.Label(header, text="🔒 Login to Your Vault", style='Title.TLabel').grid(row=0, column=0)

        # --- Form Area ---
        form = ttk.Frame(self.login_frame, style='Form.TFrame', width=400) # Fixed width for the form area
        form.grid(row=1, column=0, padx=20, pady=10, sticky="n") # Stick to top, not nsew
        form.columnconfigure(0, weight=1) # Allow entry to expand if needed later
        # form.columnconfigure(1, weight=0) # Keep checkbox column tight

        # Email
        ttk.Label(form, text="Email").grid(row=0, column=0, columnspan=2, sticky="w", pady=(10, 2))
        self.login_email_var = tk.StringVar()
        self.login_email = ttk.Entry(form, textvariable=self.login_email_var, width=40) # Set width
        self.login_email.grid(row=1, column=0, columnspan=2, sticky="ew", pady=5)
        self.login_email.bind("<KeyRelease>", lambda e: self.validate_field(self.login_email_var, self.login_email, 'email'))
        self.login_email.bind("<Return>", lambda e: self.login_password.focus_set()) # Move focus on Enter

        # Password
        ttk.Label(form, text="Password").grid(row=2, column=0, columnspan=2, sticky="w", pady=(10, 2))
        self.login_password_var = tk.StringVar()
        self.login_password = ttk.Entry(form, textvariable=self.login_password_var, show="•", width=40) # Set width
        self.login_password.grid(row=3, column=0, sticky="ew", pady=5)
        self.login_show_password_var = tk.BooleanVar(value=False)
        self.login_show_password = ttk.Checkbutton(form, text="Show", variable=self.login_show_password_var, command=lambda: self.toggle_password(self.login_password, self.login_show_password_var), style='TCheckbutton')
        self.login_show_password.grid(row=3, column=1, padx=(10,0), sticky='w') # Place next to entry
        self.login_password.bind("<Return>", lambda e: self.login()) # Login on Enter

        # Buttons
        self.login_button = ttk.Button(form, text="Login", style='Primary.TButton', command=self.login, width=15)
        self.login_button.grid(row=4, column=0, columnspan=2, pady=(30, 10)) # Centered

        link_frame = ttk.Frame(form, style='Form.TFrame')
        link_frame.grid(row=5, column=0, columnspan=2, pady=(10, 20), sticky="ew")
        link_frame.columnconfigure(0, weight=1)
        link_frame.columnconfigure(1, weight=1)

        reg_button = ttk.Button(link_frame, text="Register New Account", style='Secondary.TButton', command=lambda: self.show_form("register"))
        reg_button.grid(row=0, column=0, sticky="ew", padx=5)

        rec_button = ttk.Button(link_frame, text="Forgot Password?", style='Secondary.TButton', command=lambda: self.show_form("recover"))
        rec_button.grid(row=0, column=1, sticky="ew", padx=5)

    def create_register_form(self):
        self.register_frame = ttk.Frame(self.root, style='TFrame', name='register_frame')
        self.register_frame.columnconfigure(0, weight=1)

        # Header
        header = ttk.Frame(self.register_frame, style='Header.TFrame')
        header.grid(row=0, column=0, pady=(40, 20), sticky="ew")
        header.columnconfigure(0, weight=1)
        ttk.Label(header, text="👤 Create Your Account", style='Title.TLabel').grid(row=0, column=0, sticky='w', padx=20)
        ttk.Button(header, text="← Back", style='Secondary.TButton', command=self.go_back).grid(row=0, column=1, sticky="e", padx=20)

        # Form Area
        form = ttk.Frame(self.register_frame, style='Form.TFrame', width=450)
        form.grid(row=1, column=0, padx=20, pady=10, sticky="n")
        form.columnconfigure(0, weight=1)

        # Name
        ttk.Label(form, text="Full Name").grid(row=0, column=0, columnspan=2, sticky="w", pady=(10, 2))
        self.register_name_var = tk.StringVar()
        self.register_name = ttk.Entry(form, textvariable=self.register_name_var, width=50)
        self.register_name.grid(row=1, column=0, columnspan=2, sticky="ew", pady=5)
        self.register_name.bind("<KeyRelease>", lambda e: self.validate_field(self.register_name_var, self.register_name, 'non_empty'))
        self.register_name.bind("<Return>", lambda e: self.register_email.focus_set())

        # Email
        ttk.Label(form, text="Email Address").grid(row=2, column=0, columnspan=2, sticky="w", pady=(10, 2))
        self.register_email_var = tk.StringVar()
        self.register_email = ttk.Entry(form, textvariable=self.register_email_var, width=50)
        self.register_email.grid(row=3, column=0, columnspan=2, sticky="ew", pady=5)
        self.register_email.bind("<KeyRelease>", lambda e: self.validate_field(self.register_email_var, self.register_email, 'email'))
        self.register_email.bind("<Return>", lambda e: self.register_password.focus_set())

        # Password
        ttk.Label(form, text="Choose a Strong Password").grid(row=4, column=0, columnspan=2, sticky="w", pady=(10, 2))
        self.register_password_var = tk.StringVar()
        self.register_password = ttk.Entry(form, textvariable=self.register_password_var, show="•", width=50)
        self.register_password.grid(row=5, column=0, sticky="ew", pady=5)
        self.register_show_password_var = tk.BooleanVar(value=False)
        self.register_show_password = ttk.Checkbutton(form, text="Show", variable=self.register_show_password_var, command=lambda: self.toggle_password(self.register_password, self.register_show_password_var))
        self.register_show_password.grid(row=5, column=1, padx=(10,0), sticky='w')
        self.register_password.bind("<KeyRelease>", lambda e: self.validate_password_strength())
        self.register_password.bind("<Return>", lambda e: self.register()) # Register on Enter from password field

        # Password Strength Indicator
        self.password_strength_frame = ttk.Frame(form, style='Form.TFrame')
        self.password_strength_frame.grid(row=6, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        self.password_strength_bar = ttk.Progressbar(self.password_strength_frame, orient='horizontal', length=100, mode='determinate')
        self.password_strength_bar.grid(row=0, column=0, sticky='ew', padx=(0, 5))
        self.password_strength_label = ttk.Label(self.password_strength_frame, text="Strength: -", font=('Segoe UI', 9))
        self.password_strength_label.grid(row=0, column=1, sticky='w')
        self.password_strength_frame.columnconfigure(0, weight=1) # Let bar expand

        # Register Button
        self.register_button = ttk.Button(form, text="Register", style='Primary.TButton', command=self.register, width=15)
        self.register_button.grid(row=7, column=0, columnspan=2, pady=(20, 10))

    def create_recovery_form(self):
        self.recover_frame = ttk.Frame(self.root, style='TFrame', name='recover_frame')
        self.recover_frame.columnconfigure(0, weight=1)

        # Header
        header = ttk.Frame(self.recover_frame, style='Header.TFrame')
        header.grid(row=0, column=0, pady=(40, 20), sticky="ew")
        header.columnconfigure(0, weight=1)
        ttk.Label(header, text="🔑 Recover Your Account", style='Title.TLabel').grid(row=0, column=0, sticky='w', padx=20)
        ttk.Button(header, text="← Back", style='Secondary.TButton', command=self.go_back).grid(row=0, column=1, sticky="e", padx=20)

        # Form Area
        form = ttk.Frame(self.recover_frame, style='Form.TFrame', width=450)
        form.grid(row=1, column=0, padx=20, pady=10, sticky="n")
        form.columnconfigure(0, weight=1)

        ttk.Label(form, text="Enter your registered Email or Recovery Email:").grid(row=0, column=0, sticky="w", pady=(10, 2))
        self.recovery_email_var = tk.StringVar()
        self.recovery_email = ttk.Entry(form, textvariable=self.recovery_email_var, width=50)
        self.recovery_email.grid(row=1, column=0, sticky="ew", pady=5)
        self.recovery_email.bind("<KeyRelease>", lambda e: self.validate_field(self.recovery_email_var, self.recovery_email, 'email'))
        self.recovery_email.bind("<Return>", lambda e: self.recover_account())

        self.recover_button = ttk.Button(form, text="Send Recovery Instructions", style='Primary.TButton', command=self.recover_account, width=25)
        self.recover_button.grid(row=2, column=0, pady=(30, 10))

        # Note: Actual email sending is not implemented here.
        ttk.Label(form, text="Note: This function currently verifies the email exists.\nActual password reset email sending requires setup.", justify=tk.CENTER, font=('Segoe UI', 9)).grid(row=3, column=0, pady=(20, 0))

    def create_dashboard(self):
        self.dashboard_frame = ttk.Frame(self.root, style='TFrame', name='dashboard_frame')
        self.dashboard_frame.columnconfigure(0, weight=1)
        self.dashboard_frame.rowconfigure(2, weight=1) # Treeview row should expand

        # Header
        header = ttk.Frame(self.dashboard_frame, style='Header.TFrame')
        header.grid(row=0, column=0, pady=(20, 10), sticky="ew", padx=10)
        header.columnconfigure(1, weight=1) # Push buttons to sides
        self.welcome_label = ttk.Label(header, text="🔐 Your Passwords", style='Title.TLabel')
        self.welcome_label.grid(row=0, column=0, sticky='w')
        profile_button = ttk.Button(header, text="Edit Profile", style='Secondary.TButton', command=lambda: self.show_form("edit_profile"))
        profile_button.grid(row=0, column=2, sticky="e", padx=5)
        logout_button = ttk.Button(header, text="Log Out", style='Danger.TButton', command=self.logout)
        logout_button.grid(row=0, column=3, sticky="e", padx=5)


        # Toolbar (Search)
        toolbar = ttk.Frame(self.dashboard_frame, style='Form.TFrame')
        toolbar.grid(row=1, column=0, pady=10, sticky="ew", padx=10)
        toolbar.columnconfigure(0, weight=1) # Search entry expands

        self.search_entry_var = tk.StringVar()
        self.search_entry = ttk.Entry(toolbar, textvariable=self.search_entry_var, width=50)
        self.search_entry.grid(row=0, column=0, padx=(0, 5), sticky="ew")
        self.search_entry.bind("<KeyRelease>", lambda e: self.search_passwords()) # Search as you type
        search_button = ttk.Button(toolbar, text="🔍 Search", style='Secondary.TButton', command=self.search_passwords)
        search_button.grid(row=0, column=1, padx=5)
        clear_button = ttk.Button(toolbar, text="Clear", style='TButton', command=self.clear_search)
        clear_button.grid(row=0, column=2, padx=5)


        # Treeview Frame (for scrollbar)
        tree_frame = ttk.Frame(self.dashboard_frame, style='TFrame')
        tree_frame.grid(row=2, column=0, sticky="nsew", padx=10)
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)

        # Treeview (Password List)
        self.tree = ttk.Treeview(tree_frame, columns=('ID', 'Website/App', 'Username', 'Email'), show='headings', style='Treeview')
        self.tree.heading('ID', text='ID')
        self.tree.heading('Website/App', text='Website/App')
        self.tree.heading('Username', text='Username')
        self.tree.heading('Email', text='Email')

        # Set column widths and hide ID column by default
        self.tree.column('ID', width=0, stretch=tk.NO, anchor='center') # Hide ID column visually
        self.tree.column('Website/App', width=250, anchor='w')
        self.tree.column('Username', width=200, anchor='w')
        self.tree.column('Email', width=300, anchor='w')

        self.tree.grid(row=0, column=0, sticky="nsew")

        # Scrollbar
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview, style='Vertical.TScrollbar')
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=scrollbar.set)

        # Bind double-click to edit
        self.tree.bind("<Double-1>", lambda e: self.edit_selected_password())


        # Action Buttons Frame
        buttons_frame = ttk.Frame(self.dashboard_frame, style='Form.TFrame')
        buttons_frame.grid(row=3, column=0, pady=(15, 10), sticky="ew", padx=10)
        # Center buttons in the frame
        buttons_frame.columnconfigure(0, weight=1)
        buttons_frame.columnconfigure(1, weight=1)
        buttons_frame.columnconfigure(2, weight=1)

        add_button = ttk.Button(buttons_frame, text="➕ Add New", style='Primary.TButton', command=lambda: self.show_form("add_password"))
        add_button.grid(row=0, column=0, padx=10, sticky='e')

        edit_button = ttk.Button(buttons_frame, text="✏️ Edit Selected", style='Secondary.TButton', command=self.edit_selected_password)
        edit_button.grid(row=0, column=1, padx=10, sticky='ew')

        delete_button = ttk.Button(buttons_frame, text="🗑️ Delete Selected", style='Danger.TButton', command=self.delete_password)
        delete_button.grid(row=0, column=2, padx=10, sticky='w')


    def create_edit_profile_form(self):
        self.edit_profile_frame = ttk.Frame(self.root, style='TFrame', name='edit_profile_frame')
        self.edit_profile_frame.columnconfigure(0, weight=1)

        # Header
        header = ttk.Frame(self.edit_profile_frame, style='Header.TFrame')
        header.grid(row=0, column=0, pady=(40, 20), sticky="ew")
        header.columnconfigure(0, weight=1)
        ttk.Label(header, text="⚙️ Edit Your Profile", style='Title.TLabel').grid(row=0, column=0, sticky='w', padx=20)
        ttk.Button(header, text="← Back to Dashboard", style='Secondary.TButton', command=self.go_back).grid(row=0, column=1, sticky="e", padx=20)

        # Form Area
        form = ttk.Frame(self.edit_profile_frame, style='Form.TFrame', width=450)
        form.grid(row=1, column=0, padx=20, pady=10, sticky="n")
        form.columnconfigure(0, weight=1)

        # Username (Name)
        ttk.Label(form, text="Name").grid(row=0, column=0, columnspan=2, sticky="w", pady=(10, 2))
        self.edit_username_var = tk.StringVar()
        self.edit_username = ttk.Entry(form, textvariable=self.edit_username_var, width=50)
        self.edit_username.grid(row=1, column=0, columnspan=2, sticky="ew", pady=5)

        # Password (Optional change)
        ttk.Label(form, text="New Password (leave blank to keep current)").grid(row=2, column=0, columnspan=2, sticky="w", pady=(10, 2))
        self.edit_password_var = tk.StringVar()
        self.edit_password = ttk.Entry(form, textvariable=self.edit_password_var, show="•", width=50)
        self.edit_password.grid(row=3, column=0, sticky="ew", pady=5)
        self.edit_show_password_var = tk.BooleanVar(value=False)
        self.edit_show_password = ttk.Checkbutton(form, text="Show", variable=self.edit_show_password_var, command=lambda: self.toggle_password(self.edit_password, self.edit_show_password_var))
        self.edit_show_password.grid(row=3, column=1, padx=(10,0), sticky='w')
        # Add password strength validation if needed here too

        # Recovery Email
        ttk.Label(form, text="Recovery Email").grid(row=4, column=0, columnspan=2, sticky="w", pady=(10, 2))
        self.edit_recovery_email_var = tk.StringVar()
        self.edit_recovery_email = ttk.Entry(form, textvariable=self.edit_recovery_email_var, width=50)
        self.edit_recovery_email.grid(row=5, column=0, columnspan=2, sticky="ew", pady=5)
        self.edit_recovery_email.bind("<KeyRelease>", lambda e: self.validate_field(self.edit_recovery_email_var, self.edit_recovery_email, 'email'))

        # PIN (Optional change)
        ttk.Label(form, text="New PIN (4 digits, optional, leave blank to keep) ").grid(row=6, column=0, sticky="w", pady=(10, 2))
        self.edit_pin_var = tk.StringVar()
        # Simple validation to allow only digits and max 4 chars
        validate_pin_cmd = self.root.register(lambda P: P.isdigit() and len(P) <= 4 or P == "")
        self.edit_pin = ttk.Entry(form, textvariable=self.edit_pin_var, show="•", width=10, validate='key', validatecommand=(validate_pin_cmd, '%P'))
        self.edit_pin.grid(row=7, column=0, sticky="w", pady=5) # Align left, smaller width
        self.edit_show_pin_var = tk.BooleanVar(value=False)
        self.edit_show_pin = ttk.Checkbutton(form, text="Show", variable=self.edit_show_pin_var, command=lambda: self.toggle_password(self.edit_pin, self.edit_show_pin_var))
        self.edit_show_pin.grid(row=7, column=1, padx=(10,0), sticky='w') # Place next to entry

        # Buttons Frame
        buttons_frame = ttk.Frame(form, style='Form.TFrame')
        buttons_frame.grid(row=8, column=0, columnspan=2, pady=(30, 10), sticky='ew')
        buttons_frame.columnconfigure(0, weight=1)
        buttons_frame.columnconfigure(1, weight=1)

        # Note: "Request New PIN" might be better placed elsewhere or as a separate feature
        # For now, it just generates and updates the DB - no actual sending.
        # request_pin_button = ttk.Button(buttons_frame, text="Generate & Set New PIN", style='Secondary.TButton', command=self.request_new_pin)
        # request_pin_button.grid(row=0, column=0, padx=5, sticky='ew')

        self.save_profile_button = ttk.Button(buttons_frame, text="Save Profile Changes", style='Primary.TButton', command=self.save_profile_changes)
        self.save_profile_button.grid(row=0, column=0, columnspan=2, padx=5, sticky='ew') # Make save button span if PIN button removed/relocated


    def create_add_password_form(self):
        self.add_password_frame = ttk.Frame(self.root, style='TFrame', name='add_password_frame')
        self.add_password_frame.columnconfigure(0, weight=1)

        # Header
        header = ttk.Frame(self.add_password_frame, style='Header.TFrame')
        header.grid(row=0, column=0, pady=(40, 20), sticky="ew")
        header.columnconfigure(0, weight=1)
        ttk.Label(header, text="➕ Add New Password Entry", style='Title.TLabel').grid(row=0, column=0, sticky='w', padx=20)
        ttk.Button(header, text="← Back to Dashboard", style='Secondary.TButton', command=self.go_back).grid(row=0, column=1, sticky="e", padx=20)

        # Form Area
        form = ttk.Frame(self.add_password_frame, style='Form.TFrame', width=450)
        form.grid(row=1, column=0, padx=20, pady=10, sticky="n")
        form.columnconfigure(0, weight=1)

        # App Name
        ttk.Label(form, text="Website or Application Name").grid(row=0, column=0, columnspan=2, sticky="w", pady=(10, 2))
        self.add_app_name_var = tk.StringVar()
        self.add_app_name = ttk.Entry(form, textvariable=self.add_app_name_var, width=50)
        self.add_app_name.grid(row=1, column=0, columnspan=2, sticky="ew", pady=5)
        self.add_app_name.bind("<Return>", lambda e: self.add_username.focus_set())

        # Username
        ttk.Label(form, text="Username / Login ID").grid(row=2, column=0, columnspan=2, sticky="w", pady=(10, 2))
        self.add_username_var = tk.StringVar()
        self.add_username = ttk.Entry(form, textvariable=self.add_username_var, width=50)
        self.add_username.grid(row=3, column=0, columnspan=2, sticky="ew", pady=5)
        self.add_username.bind("<Return>", lambda e: self.add_password.focus_set())


        # Password
        ttk.Label(form, text="Password").grid(row=4, column=0, columnspan=2, sticky="w", pady=(10, 2))
        self.add_password_var = tk.StringVar()
        self.add_password = ttk.Entry(form, textvariable=self.add_password_var, show="•", width=50)
        self.add_password.grid(row=5, column=0, sticky="ew", pady=5)
        self.add_show_password_var = tk.BooleanVar(value=False)
        self.add_show_password = ttk.Checkbutton(form, text="Show", variable=self.add_show_password_var, command=lambda: self.toggle_password(self.add_password, self.add_show_password_var))
        self.add_show_password.grid(row=5, column=1, padx=(10,0), sticky='w')
        self.add_password.bind("<Return>", lambda e: self.add_email.focus_set())

        # Email
        ttk.Label(form, text="Associated Email (Optional)").grid(row=6, column=0, columnspan=2, sticky="w", pady=(10, 2))
        self.add_email_var = tk.StringVar()
        self.add_email = ttk.Entry(form, textvariable=self.add_email_var, width=50)
        self.add_email.grid(row=7, column=0, columnspan=2, sticky="ew", pady=5)
        self.add_email.bind("<KeyRelease>", lambda e: self.validate_field(self.add_email_var, self.add_email, 'email_optional'))
        self.add_email.bind("<Return>", lambda e: self.save_new_password())

        # Add Button
        self.save_password_button = ttk.Button(form, text="Save New Password", style='Primary.TButton', command=self.save_new_password, width=20)
        self.save_password_button.grid(row=8, column=0, columnspan=2, pady=(30, 10))

    def create_edit_password_form(self):
        self.edit_password_frame = ttk.Frame(self.root, style='TFrame', name='edit_password_frame')
        self.edit_password_frame.columnconfigure(0, weight=1)

        # Header
        header = ttk.Frame(self.edit_password_frame, style='Header.TFrame')
        header.grid(row=0, column=0, pady=(40, 20), sticky="ew")
        header.columnconfigure(0, weight=1)
        ttk.Label(header, text="✏️ Edit Password Entry", style='Title.TLabel').grid(row=0, column=0, sticky='w', padx=20)
        ttk.Button(header, text="← Back to Dashboard", style='Secondary.TButton', command=self.go_back).grid(row=0, column=1, sticky="e", padx=20)

        # Form Area
        form = ttk.Frame(self.edit_password_frame, style='Form.TFrame', width=450)
        form.grid(row=1, column=0, padx=20, pady=10, sticky="n")
        form.columnconfigure(0, weight=1)

        # App Name
        ttk.Label(form, text="Website or Application Name").grid(row=0, column=0, columnspan=2, sticky="w", pady=(10, 2))
        self.edit_app_name_var = tk.StringVar()
        self.edit_app_name = ttk.Entry(form, textvariable=self.edit_app_name_var, width=50)
        self.edit_app_name.grid(row=1, column=0, columnspan=2, sticky="ew", pady=5)
        self.edit_app_name.bind("<Return>", lambda e: self.edit_password_username.focus_set())


        # Username
        ttk.Label(form, text="Username / Login ID").grid(row=2, column=0, columnspan=2, sticky="w", pady=(10, 2))
        self.edit_password_username_var = tk.StringVar()
        self.edit_password_username = ttk.Entry(form, textvariable=self.edit_password_username_var, width=50)
        self.edit_password_username.grid(row=3, column=0, columnspan=2, sticky="ew", pady=5)
        self.edit_password_username.bind("<Return>", lambda e: self.edit_password_password.focus_set())


        # Password
        ttk.Label(form, text="Password").grid(row=4, column=0, columnspan=2, sticky="w", pady=(10, 2))
        self.edit_password_password_var = tk.StringVar()
        self.edit_password_password = ttk.Entry(form, textvariable=self.edit_password_password_var, show="•", width=50)
        self.edit_password_password.grid(row=5, column=0, sticky="ew", pady=5)
        self.edit_password_show_var = tk.BooleanVar(value=False)
        self.edit_show_password_check = ttk.Checkbutton(form, text="Show", variable=self.edit_password_show_var, command=lambda: self.toggle_password(self.edit_password_password, self.edit_password_show_var))
        self.edit_show_password_check.grid(row=5, column=1, padx=(10,0), sticky='w')
        self.edit_password_password.bind("<Return>", lambda e: self.edit_password_email.focus_set())


        # Email
        ttk.Label(form, text="Associated Email (Optional)").grid(row=6, column=0, columnspan=2, sticky="w", pady=(10, 2))
        self.edit_password_email_var = tk.StringVar()
        self.edit_password_email = ttk.Entry(form, textvariable=self.edit_password_email_var, width=50)
        self.edit_password_email.grid(row=7, column=0, columnspan=2, sticky="ew", pady=5)
        self.edit_password_email.bind("<KeyRelease>", lambda e: self.validate_field(self.edit_password_email_var, self.edit_password_email, 'email_optional'))
        self.edit_password_email.bind("<Return>", lambda e: self.save_edited_password())


        # Save Button
        self.save_edits_button = ttk.Button(form, text="Save Changes", style='Primary.TButton', command=self.save_edited_password, width=20)
        self.save_edits_button.grid(row=8, column=0, columnspan=2, pady=(30, 10))

    # --- Utility and Validation Methods ---

    def toggle_password(self, entry_widget, show_var):
        """Toggles the visibility of the password in an Entry widget."""
        if show_var.get():
            entry_widget.configure(show="")
        else:
            entry_widget.configure(show="•")

    def validate_field(self, string_var, entry_widget, validation_type='email'):
        """Validates the content of an entry field and updates its style."""
        value = string_var.get().strip()
        is_valid = False

        if not value: # Empty field is generally considered valid until submission (unless required)
             entry_widget.configure(style='TEntry') # Reset style if cleared
             return # Don't show error for empty field during typing

        if validation_type == 'email':
            is_valid = self.validate_email(value)
        elif validation_type == 'email_optional':
             # If it's not empty, it must be valid. Empty is okay.
             is_valid = self.validate_email(value) if value else True
        elif validation_type == 'non_empty':
            is_valid = bool(value) # True if not empty
        # Add more validation types as needed (e.g., 'password', 'pin')

        if is_valid:
            entry_widget.configure(style='TEntry')
        else:
            entry_widget.configure(style='Error.TEntry')
        return is_valid # Return status for use in submit functions


    def validate_password_strength(self):
        """Checks password strength and updates the indicator."""
        password = self.register_password_var.get()
        strength = 0
        label = "Strength: -"
        color = self.text_color # Default color

        length_criteria = len(password) >= 8
        digit_criteria = re.search(r'[0-9]', password)
        uppercase_criteria = re.search(r'[A-Z]', password)
        lowercase_criteria = re.search(r'[a-z]', password)
        symbol_criteria = re.search(r'[!@#$%^&*()_+=[\]{};\'\\:"|,./<>?~`-]', password)

        criteria_met = sum([bool(length_criteria), bool(digit_criteria), bool(uppercase_criteria), bool(lowercase_criteria), bool(symbol_criteria)])

        if len(password) == 0:
             strength = 0
             label = "Strength: -"
             color = self.text_color
        elif criteria_met <= 2:
             strength = max(25, len(password) * 5) # Basic strength based on length if weak
             label = "Strength: Weak"
             color = self.error_color
             self.style.configure('Weak.Horizontal.TProgressbar', background=self.error_color)
             self.password_strength_bar.configure(style='Weak.Horizontal.TProgressbar')
        elif criteria_met <= 4 :
            strength = 65
            label = "Strength: Medium"
            color = self.warning_color
            self.style.configure('Medium.Horizontal.TProgressbar', background=self.warning_color)
            self.password_strength_bar.configure(style='Medium.Horizontal.TProgressbar')
        else: # All 5 criteria met
            strength = 100
            label = "Strength: Strong"
            color = self.success_color
            self.style.configure('Strong.Horizontal.TProgressbar', background=self.success_color)
            self.password_strength_bar.configure(style='Strong.Horizontal.TProgressbar')


        self.password_strength_bar['value'] = strength
        self.password_strength_label.configure(text=label, foreground=color)

    def validate_email(self, email):
        """Validates email format using a regular expression."""
        # More comprehensive regex, allows for newer TLDs
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

    def show_loading(self, button, operation, original_text):
        """Disables button, shows 'Processing...', runs operation, re-enables."""
        if self.is_loading:
            return # Don't stack loading operations on the same button
        self.is_loading = True
        button.configure(state='disabled', text="Processing...")
        self.root.config(cursor="wait") # Change cursor
        self.root.update_idletasks() # Ensure UI updates

        try:
            operation() # Execute the provided function (e.g., database call)
        finally:
            # This block ensures UI is restored even if 'operation' raises an error
            self.root.config(cursor="") # Restore cursor
            button.configure(state='normal', text=original_text) # Restore original text
            self.is_loading = False

    def _execute_db_query(self, query, params=None, fetch_one=False, fetch_all=False, is_commit=False, dictionary_cursor=False):
        """Helper function to execute database queries with error handling."""
        if not self.conn or not self.conn.is_connected():
             self.connect_to_db() # Try to reconnect if disconnected
             if not self.conn or not self.conn.is_connected():
                 messagebox.showerror("Database Error", "Database connection is unavailable.")
                 return None # Indicate failure

        result = None
        try:
            # Use dictionary cursor if requested, helpful for fetching rows as dicts
            cursor = self.conn.cursor(dictionary=dictionary_cursor)
            cursor.execute(query, params or ()) # params must be a tuple or list

            if is_commit:
                self.conn.commit()
                result = cursor.lastrowid or cursor.rowcount # Return ID or affected rows for commits
            elif fetch_one:
                result = cursor.fetchone()
            elif fetch_all:
                result = cursor.fetchall()

            cursor.close()
            return result
        except mysql.connector.Error as e:
             # Log detailed error for debugging
             print(f"Database Error executing query:\nQuery: {query}\nParams: {params}\nError: {e}")
             # Provide user-friendly message
             messagebox.showerror("Database Operation Failed", f"An error occurred: {e.MySQLdb._exceptions}\nPlease check the details or contact support.")
             # Rollback if it was part of a transaction that failed mid-commit
             if is_commit:
                 try:
                     self.conn.rollback()
                 except Error as rb_err:
                     print(f"Rollback failed: {rb_err}")
             return None # Indicate failure

    # --- Action Methods (Login, Register, CRUD, etc.) ---

    def login(self):
        email = self.login_email_var.get().strip()
        password = self.login_password_var.get().strip() # PLAIN TEXT - VERY INSECURE

        # Frontend Validation
        if not self.validate_field(self.login_email_var, self.login_email, 'email'):
            messagebox.showerror("Login Error", "Invalid email format.")
            self.login_email.focus_set()
            return
        if not password:
            messagebox.showerror("Login Error", "Password cannot be empty.")
            self.login_password.focus_set()
            return

        def perform_login():
            # --- SECURITY WARNING ---
            # This retrieves the stored password (assumed plain text or easily reversible)
            # and compares it directly. NEVER do this in production.
            # 1. Retrieve the HASHED password from DB for the given email.
            # 2. Use a library like bcrypt to compare the entered password with the stored hash.
            # Example (using bcrypt):
            # query = "SELECT id, name, email, password FROM users WHERE email = %s"
            # user_data = self._execute_db_query(query, (email,), fetch_one=True, dictionary_cursor=True)
            # if user_data and bcrypt.checkpw(password.encode('utf-8'), user_data['password'].encode('utf-8')):
            #    # Password matches
            #    self.current_user = {'id': user_data['id'], 'name': user_data['name'], 'email': user_data['email']} # Don't store password hash in session
            #    # ... rest of login success logic ...
            # else:
            #    # Invalid email or password
            #    messagebox.showerror("Login Failed", "Invalid email or password.")
            # --- END SECURITY WARNING ---

            # Current insecure implementation:
            query = "SELECT id, name, email, recovery_email FROM users WHERE email = %s AND password = %s" # Comparing plain text
            user = self._execute_db_query(query, (email, password), fetch_one=True, dictionary_cursor=True)

            if user:
                self.current_user = user # Store user data (id, name, email, recovery_email)
                self.update_welcome_message()
                self.show_form("dashboard")
                # Clear login form fields after successful login
                self.login_email_var.set("")
                self.login_password_var.set("")
                self.login_show_password_var.set(False)
                self.toggle_password(self.login_password, self.login_show_password_var) # Ensure it's hidden
                messagebox.showinfo("Login Success", f"Welcome back, {self.current_user['name']}!")
            else:
                messagebox.showerror("Login Failed", "Invalid email or password.")

        # Use the show_loading wrapper
        self.show_loading(self.login_button, perform_login, "Login")

    def register(self):
        name = self.register_name_var.get().strip()
        email = self.register_email_var.get().strip()
        password = self.register_password_var.get().strip() # PLAIN TEXT - VERY INSECURE

        # Frontend Validation
        if not self.validate_field(self.register_name_var, self.register_name, 'non_empty'):
             messagebox.showerror("Registration Error", "Name cannot be empty.")
             self.register_name.focus_set()
             return
        if not self.validate_field(self.register_email_var, self.register_email, 'email'):
             messagebox.showerror("Registration Error", "Invalid email format.")
             self.register_email.focus_set()
             return
        # Add more robust password validation if needed (e.g., checking strength indicator value)
        if len(password) < 8: # Basic length check
             messagebox.showerror("Registration Error", "Password must be at least 8 characters long.")
             self.register_password.focus_set()
             return

        def perform_register():
            # --- SECURITY WARNING ---
            # HASH the password before storing it.
            # Example (using bcrypt):
            # hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            # query = "INSERT INTO users (name, email, password, recovery_email) VALUES (%s, %s, %s, %s)"
            # params = (name, email, hashed_pw.decode('utf-8'), email) # Store hash as string
            # success = self._execute_db_query(query, params, is_commit=True)
            # --- END SECURITY WARNING ---

            # Check if email already exists
            check_query = "SELECT id FROM users WHERE email = %s"
            existing_user = self._execute_db_query(check_query, (email,), fetch_one=True)
            if existing_user:
                messagebox.showerror("Registration Failed", "An account with this email already exists.")
                self.register_email.focus_set()
                return # Stop registration

            # Current insecure implementation:
            query = "INSERT INTO users (name, email, password, recovery_email) VALUES (%s, %s, %s, %s)"
            # Set recovery email same as main email by default during registration
            params = (name, email, password, email)
            success = self._execute_db_query(query, params, is_commit=True)

            if success is not None: # Check if query execution didn't return None (error)
                messagebox.showinfo("Registration Successful", "Account created successfully! Please log in.")
                # Clear registration form
                self.register_name_var.set("")
                self.register_email_var.set("")
                self.register_password_var.set("")
                self.register_show_password_var.set(False)
                self.toggle_password(self.register_password, self.register_show_password_var)
                self.validate_password_strength() # Reset strength indicator
                self.show_form("login") # Go to login screen
            else:
                # Error message already shown by _execute_db_query
                pass

        self.show_loading(self.register_button, perform_register, "Register")


    def recover_account(self):
        email = self.recovery_email_var.get().strip()

        if not self.validate_field(self.recovery_email_var, self.recovery_email, 'email'):
            messagebox.showerror("Recovery Error", "Invalid email format entered.")
            self.recovery_email.focus_set()
            return

        def perform_recovery():
            # This function SHOULD:
            # 1. Check if the email exists in `users` table (either `email` or `recovery_email` field).
            # 2. Generate a secure, time-limited recovery token.
            # 3. Store the token hashed in the DB, associated with the user ID and an expiry time.
            # 4. Send an email (using smtplib, SendGrid, etc.) containing a recovery link with the token.
            # 5. Inform the user to check their email.
            # The current implementation only checks if the email exists.

            query = "SELECT id, email FROM users WHERE email = %s OR recovery_email = %s"
            user = self._execute_db_query(query, (email, email), fetch_one=True, dictionary_cursor=True)

            if user:
                # Simulate sending email
                print(f"SIMULATING: Sending recovery instructions to {user['email']}")
                messagebox.showinfo("Recovery Initiated", f"If an account exists for {email}, recovery instructions have been sent.\nPlease check your inbox (including spam folder).")
                self.show_form("login")
                self.recovery_email_var.set("")
            else:
                # Show the same message whether the email exists or not to prevent email enumeration attacks
                messagebox.showinfo("Recovery Initiated", f"If an account exists for {email}, recovery instructions have been sent.\nPlease check your inbox (including spam folder).")
                self.show_form("login") # Still go back to login
                self.recovery_email_var.set("")

        self.show_loading(self.recover_button, perform_recovery, "Send Recovery Instructions")


    def logout(self):
        if messagebox.askyesno("Log Out", "Are you sure you want to log out?"):
            self.current_user = None
            self.editing_password = None
            # Clear dashboard list (optional, but good practice)
            for item in self.tree.get_children():
                self.tree.delete(item)
            self.search_entry_var.set("") # Clear search bar
            self.form_history = [] # Reset navigation history
            self.show_form("login")
            messagebox.showinfo("Logged Out", "You have been successfully logged out.")


    def update_welcome_message(self):
        """Updates the dashboard welcome message with the user's name."""
        if self.current_user and hasattr(self, 'welcome_label'):
            self.welcome_label.config(text=f"🔐 Welcome, {self.current_user.get('name', 'User')}!")
        elif hasattr(self, 'welcome_label'):
            self.welcome_label.config(text="🔐 Your Passwords")


    def clear_search(self):
        """Clears the search bar and refreshes the list."""
        self.search_entry_var.set("")
        self.refresh_password_list()


    def search_passwords(self):
        """Filters the password list based on the search term."""
        search_term = self.search_entry_var.get().strip().lower()
        # No need to clear here, refresh_password_list handles it
        self.refresh_password_list(search_term=search_term)


    def refresh_password_list(self, search_term=None):
        """Clears and reloads the password list in the Treeview, optionally filtering."""
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)

        if not self.current_user:
            print("Refresh skipped: No user logged in.")
            return # Exit if no user is logged in

        user_id = self.current_user.get('id')
        if not user_id:
            messagebox.showerror("Error", "User ID not found. Cannot load passwords.")
            return

        passwords = []
        try:
            if search_term:
                # --- SECURITY NOTE on LIKE ---
                # Using LIKE with user input can sometimes be inefficient on large tables
                # if indexes aren't properly set up or if the pattern starts with '%'.
                # Consider Full-Text Search for better performance if needed.
                # ---
                query = """
                    SELECT id, app, username, email
                    FROM passwords
                    WHERE user_id = %s AND (
                        LOWER(app) LIKE %s OR
                        LOWER(username) LIKE %s OR
                        LOWER(email) LIKE %s
                    )
                    ORDER BY app ASC, username ASC
                """
                search_pattern = f"%{search_term}%"
                params = (user_id, search_pattern, search_pattern, search_pattern)
            else:
                query = """
                    SELECT id, app, username, email
                    FROM passwords
                    WHERE user_id = %s
                    ORDER BY app ASC, username ASC
                """
                params = (user_id,)

            passwords = self._execute_db_query(query, params, fetch_all=True, dictionary_cursor=True)

            if passwords is not None: # Check if query succeeded
                 for pwd in passwords:
                     # Insert using the DB 'id' as the Treeview item ID (iid) for easier reference
                     self.tree.insert('', tk.END, iid=pwd['id'], values=(pwd['id'], pwd['app'], pwd['username'], pwd['email']))

        except Exception as e: # Catch potential issues during list population
             messagebox.showerror("List Error", f"An error occurred while displaying passwords: {e}")
             print(f"Error refreshing password list: {e}")


    def load_profile_data(self):
         """Loads current user data into the Edit Profile form fields."""
         if not self.current_user:
             messagebox.showerror("Error", "Not logged in.")
             self.go_back() # Go back if accessed without login
             return

         # Fetch fresh data in case it changed elsewhere (unlikely in this app structure)
         query = "SELECT name, recovery_email, pin FROM users WHERE id = %s"
         profile_data = self._execute_db_query(query, (self.current_user['id'],), fetch_one=True, dictionary_cursor=True)

         if profile_data:
             self.edit_username_var.set(profile_data.get('name', ''))
             self.edit_recovery_email_var.set(profile_data.get('recovery_email', self.current_user.get('email', ''))) # Default to main email if recovery is null
             self.edit_pin_var.set(profile_data.get('pin', '')) # Show current PIN (INSECURE if plain text)
             # Clear password field - don't pre-fill it
             self.edit_password_var.set("")
             self.edit_show_password_var.set(False)
             self.toggle_password(self.edit_password, self.edit_show_password_var)
             self.edit_show_pin_var.set(False)
             self.toggle_password(self.edit_pin, self.edit_show_pin_var)
         else:
             messagebox.showerror("Error", "Could not load profile data.")
             self.go_back()


    def request_new_pin(self):
        """Generates a random 4-digit PIN and updates the DB (simulation)."""
        if not self.current_user:
            messagebox.showerror("Error", "Please log in first.")
            return

        # Basic PIN generation (replace with cryptographically secure if needed)
        new_pin = str(random.randint(1000, 9999))

        # --- SECURITY WARNING ---
        # Storing PINs (even temporary ones) in plain text is insecure.
        # Consider hashing or encrypting them, or using a different verification method.
        # ---
        query = "UPDATE users SET pin = %s WHERE id = %s"
        success = self._execute_db_query(query, (new_pin, self.current_user['id']), is_commit=True)

        if success is not None:
             # Simulate sending PIN via email
             print(f"SIMULATING: New PIN {new_pin} generated for user {self.current_user['id']}. 'Sent' to {self.current_user.get('recovery_email') or self.current_user.get('email')}")
             messagebox.showinfo("PIN Generated", f"A new 4-digit PIN has been generated and set for your account.\n(Simulated: {new_pin})\nIn a real app, this would be sent to your recovery email.")
             # Update the PIN field in the form immediately
             self.edit_pin_var.set(new_pin)
             self.edit_show_pin_var.set(True) # Show the newly generated PIN
             self.toggle_password(self.edit_pin, self.edit_show_pin_var)
        else:
             messagebox.showerror("Error", "Failed to update PIN in the database.")


    def save_profile_changes(self):
        if not self.current_user:
             messagebox.showerror("Error", "Not logged in.")
             return

        # Get values from the form
        new_name = self.edit_username_var.get().strip()
        new_password = self.edit_password_var.get() # Don't strip(), allow spaces if intended
        new_recovery_email = self.edit_recovery_email_var.get().strip()
        new_pin = self.edit_pin_var.get().strip()

        # --- Validation ---
        if not new_name:
             messagebox.showerror("Validation Error", "Name cannot be empty.")
             self.edit_username.focus_set()
             return
        if new_recovery_email and not self.validate_email(new_recovery_email):
             messagebox.showerror("Validation Error", "Invalid format for Recovery Email.")
             self.edit_recovery_email.focus_set()
             return
        if new_pin and (not new_pin.isdigit() or len(new_pin) != 4):
             messagebox.showerror("Validation Error", "PIN must be exactly 4 digits.")
             self.edit_pin.focus_set()
             return
        # Basic password length check if a new password was entered
        if new_password and len(new_password) < 8:
            messagebox.showerror("Validation Error", "New password must be at least 8 characters.")
            self.edit_password.focus_set()
            return

        def perform_save():
            updates = []
            params = []

            # Check current values to see if changes were actually made (optional optimization)
            # Could fetch current values again here if high concurrency is expected

            # Add name if changed (assuming self.current_user holds reasonably current data)
            if new_name != self.current_user.get('name'):
                updates.append("name = %s")
                params.append(new_name)

            # Add password if a new one was provided
            if new_password:
                # --- SECURITY: HASH the new password ---
                # hashed_pw = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                # updates.append("password = %s")
                # params.append(hashed_pw)
                # --- Current insecure version ---
                updates.append("password = %s")
                params.append(new_password)

            # Add recovery email if changed
            # Fetch current recovery email for comparison if necessary
            current_recovery = self._execute_db_query("SELECT recovery_email FROM users WHERE id = %s", (self.current_user['id'],), fetch_one=True)
            current_recovery_email = current_recovery[0] if current_recovery else self.current_user.get('email') # Fallback
            if new_recovery_email and new_recovery_email != current_recovery_email:
                updates.append("recovery_email = %s")
                params.append(new_recovery_email)

            # Add PIN if changed
            # Fetch current PIN for comparison if necessary
            current_pin_tuple = self._execute_db_query("SELECT pin FROM users WHERE id = %s", (self.current_user['id'],), fetch_one=True)
            current_pin = current_pin_tuple[0] if current_pin_tuple else None
            # Update if new PIN is provided and different, or if clearing an existing PIN
            if (new_pin and new_pin != current_pin) or (not new_pin and current_pin):
                 # --- SECURITY: Consider hashing/encrypting PIN ---
                 updates.append("pin = %s")
                 params.append(new_pin if new_pin else None) # Store NULL if cleared

            if not updates:
                messagebox.showinfo("No Changes", "No changes were detected in your profile.")
                return # Exit if nothing to update

            # Build the final query
            query = f"UPDATE users SET {', '.join(updates)} WHERE id = %s"
            params.append(self.current_user['id'])

            success = self._execute_db_query(query, params, is_commit=True)

            if success is not None:
                 messagebox.showinfo("Success", "Profile updated successfully.")
                 # Update current_user dictionary locally if needed
                 if new_name != self.current_user.get('name'): self.current_user['name'] = new_name
                 if new_recovery_email and new_recovery_email != current_recovery_email: self.current_user['recovery_email'] = new_recovery_email
                 # Update welcome message if name changed
                 self.update_welcome_message()
                 self.show_form("dashboard") # Go back to dashboard
            else:
                 # Error message shown by _execute_db_query
                 pass

        self.show_loading(self.save_profile_button, perform_save, "Save Profile Changes")


    def save_new_password(self):
        app = self.add_app_name_var.get().strip()
        username = self.add_username_var.get().strip()
        password = self.add_password_var.get() # Don't strip password
        email = self.add_email_var.get().strip()

        # Validation
        if not app:
             messagebox.showerror("Validation Error", "Website/App name cannot be empty.")
             self.add_app_name.focus_set()
             return
        if not username:
             messagebox.showerror("Validation Error", "Username cannot be empty.")
             self.add_username.focus_set()
             return
        if not password:
             messagebox.showerror("Validation Error", "Password cannot be empty.")
             self.add_password.focus_set()
             return
        # Email is optional, but validate if provided
        if email and not self.validate_email(email):
             messagebox.showerror("Validation Error", "Invalid format for associated email.")
             self.add_email.focus_set()
             return
        if not self.current_user:
             messagebox.showerror("Error", "Not logged in.")
             return

        def perform_save():
             # --- SECURITY WARNING ---
             # Encrypt the 'password' before storing it. Use a strong symmetric algorithm
             # (like AES-GCM) with a key derived from the user's master password or stored securely.
             # DO NOT STORE PLAIN TEXT PASSWORDS.
             # Example placeholder: encrypted_password = encrypt_function(password, user_key)
             # --- END WARNING ---

             query = """
                 INSERT INTO passwords (user_id, app, username, password, email)
                 VALUES (%s, %s, %s, %s, %s)
             """
             # Using insecure plain text password storage:
             params = (self.current_user['id'], app, username, password, email if email else '') # Store empty string if email not provided

             success = self._execute_db_query(query, params, is_commit=True)

             if success is not None:
                 self.refresh_password_list() # Update the list on the dashboard
                 messagebox.showinfo("Success", f"Password entry for '{app}' added successfully.")
                 self.show_form("dashboard") # Go back to dashboard
                 # Clear the add form
                 self.add_app_name_var.set("")
                 self.add_username_var.set("")
                 self.add_password_var.set("")
                 self.add_email_var.set("")
                 self.add_show_password_var.set(False)
                 self.toggle_password(self.add_password, self.add_show_password_var)
             else:
                 # Error message shown by _execute_db_query
                 pass

        self.show_loading(self.save_password_button, perform_save, "Save New Password")


    def edit_selected_password(self):
        """Loads the selected password data into the edit form."""
        selected_items = self.tree.selection() # Get tuple of selected item IDs (iids)
        if not selected_items:
            messagebox.showwarning("Selection Error", "Please select a password entry from the list to edit.")
            return

        if len(selected_items) > 1:
             messagebox.showwarning("Selection Error", "Please select only one entry to edit at a time.")
             return

        selected_iid = selected_items[0] # Get the actual item ID (which we set as the DB id)

        if not self.current_user:
             messagebox.showerror("Error", "Not logged in.")
             return

        def perform_load_for_edit():
            # Fetch the full password details, including the actual password (INSECURE)
            # --- SECURITY WARNING ---
            # This fetches the stored password (assumed plain text or easily decrypted).
            # In a secure system, you wouldn't typically fetch the password itself back
            # unless absolutely necessary and handled very carefully (e.g., for reveal on demand).
            # Editing would often involve setting a *new* password, not viewing the old one.
            # If decryption is needed, it should happen here:
            # raw_password = decrypt_function(pwd_data['password'], user_key)
            # --- END WARNING ---
            query = """
                SELECT id, app, username, password, email
                FROM passwords
                WHERE id = %s AND user_id = %s
            """
            params = (selected_iid, self.current_user['id'])
            pwd_data = self._execute_db_query(query, params, fetch_one=True, dictionary_cursor=True)

            if pwd_data:
                self.editing_password = pwd_data # Store the dict of the password being edited
                # Populate the edit form fields
                self.edit_app_name_var.set(pwd_data['app'])
                self.edit_password_username_var.set(pwd_data['username'])
                self.edit_password_password_var.set(pwd_data['password']) # Populating with plain text (INSECURE)
                self.edit_password_email_var.set(pwd_data['email'])
                # Reset show password checkbox
                self.edit_password_show_var.set(False)
                self.toggle_password(self.edit_password_password, self.edit_password_show_var)

                self.show_form("edit_password")
                self.edit_app_name.focus_set() # Set focus to first field
            else:
                messagebox.showerror("Error", "Could not retrieve password details.\nThe entry might have been deleted or modified.")
                self.refresh_password_list() # Refresh list in case it's outdated

        # Although fast, use loading for consistency if DB access is involved
        # Find the edit button on the dashboard to show loading (might need a better way to reference it)
        edit_button = self.dashboard_frame.winfo_children()[3].winfo_children()[1] # Fragile way to find button
        self.show_loading(edit_button, perform_load_for_edit, "✏️ Edit Selected")


    def save_edited_password(self):
        """Saves the changes made in the edit password form."""
        if not self.editing_password or not self.current_user:
            messagebox.showerror("Error", "No password entry is currently being edited or you are not logged in.")
            self.show_form("dashboard") # Go back if state is invalid
            return

        # Get updated values
        app = self.edit_app_name_var.get().strip()
        username = self.edit_password_username_var.get().strip()
        password = self.edit_password_password_var.get() # Don't strip password
        email = self.edit_password_email_var.get().strip()

        # --- Validation (similar to add password) ---
        if not app:
             messagebox.showerror("Validation Error", "Website/App name cannot be empty.")
             self.edit_app_name.focus_set()
             return
        if not username:
             messagebox.showerror("Validation Error", "Username cannot be empty.")
             self.edit_password_username.focus_set()
             return
        if not password:
             messagebox.showerror("Validation Error", "Password cannot be empty.")
             self.edit_password_password.focus_set()
             return
        if email and not self.validate_email(email):
             messagebox.showerror("Validation Error", "Invalid format for associated email.")
             self.edit_password_email.focus_set()
             return

        # Check if any actual changes were made (optional)
        if (app == self.editing_password['app'] and
            username == self.editing_password['username'] and
            password == self.editing_password['password'] and # Comparing plain text (INSECURE)
            email == self.editing_password['email']):
            messagebox.showinfo("No Changes", "No changes detected for this password entry.")
            self.show_form("dashboard") # Go back
            return

        def perform_save_edit():
            # --- SECURITY WARNING ---
            # Encrypt the 'password' before updating.
            # Example placeholder: encrypted_password = encrypt_function(password, user_key)
            # --- END WARNING ---

            query = """
                UPDATE passwords
                SET app = %s, username = %s, password = %s, email = %s
                WHERE id = %s AND user_id = %s
            """
            # Using insecure plain text password storage:
            params = (app, username, password, email if email else '', self.editing_password['id'], self.current_user['id'])

            success = self._execute_db_query(query, params, is_commit=True)

            if success is not None and success > 0: # Check if rows were affected
                 self.refresh_password_list() # Update the list
                 messagebox.showinfo("Success", f"Password entry for '{app}' updated successfully.")
                 self.show_form("dashboard") # Go back to dashboard
                 # Clear edit form and editing state
                 self.edit_app_name_var.set("")
                 self.edit_password_username_var.set("")
                 self.edit_password_password_var.set("")
                 self.edit_password_email_var.set("")
                 self.editing_password = None
            elif success == 0:
                 messagebox.showwarning("Update Failed", "The password entry could not be updated. It might have been deleted.")
                 self.refresh_password_list() # Refresh to show current state
                 self.show_form("dashboard")
            else:
                 # Error already shown by _execute_db_query
                 pass

        self.show_loading(self.save_edits_button, perform_save_edit, "Save Changes")


    def delete_password(self):
        """Deletes the selected password entry from the database."""
        selected_items = self.tree.selection()
        if not selected_items:
            messagebox.showwarning("Selection Error", "Please select a password entry to delete.")
            return

        if not self.current_user:
             messagebox.showerror("Error", "Not logged in.")
             return

        # Confirmation dialog
        confirm_msg = "Are you sure you want to permanently delete the selected password entry?"
        if len(selected_items) > 1:
             confirm_msg = f"Are you sure you want to permanently delete the {len(selected_items)} selected password entries?"

        if not messagebox.askyesno("Confirm Deletion", confirm_msg):
            return

        deleted_count = 0
        failed_ids = []

        def perform_delete():
            nonlocal deleted_count, failed_ids
            # Iterate through all selected iids
            for item_iid in selected_items:
                query = "DELETE FROM passwords WHERE id = %s AND user_id = %s"
                params = (item_iid, self.current_user['id'])
                # is_commit=True returns rowcount for DELETE on some connectors/versions
                rows_affected = self._execute_db_query(query, params, is_commit=True)

                if rows_affected is not None and rows_affected > 0:
                    deleted_count += 1
                elif rows_affected == 0:
                    print(f"Warning: No rows deleted for ID {item_iid}. Might have already been deleted.")
                    failed_ids.append(item_iid) # Track potential issues
                else: # Error occurred during deletion of this item
                    failed_ids.append(item_iid)
                    # Stop processing further items if one fails? Optional.
                    # messagebox.showerror("Deletion Error", f"Failed to delete item with ID {item_iid}. Aborting further deletions.")
                    # break

            # --- Post-deletion feedback ---
            if deleted_count > 0:
                message = f"{deleted_count} password entr{'y' if deleted_count == 1 else 'ies'} deleted successfully."
                if failed_ids:
                    message += f"\nCould not delete {len(failed_ids)} entr{'y' if len(failed_ids) == 1 else 'ies'} (IDs: {', '.join(map(str, failed_ids))}). They may have already been removed."
                    messagebox.showwarning("Partial Deletion", message)
                else:
                    messagebox.showinfo("Success", message)
            elif failed_ids:
                 messagebox.showerror("Deletion Failed", f"Could not delete the selected entr{'y' if len(failed_ids) == 1 else 'ies'}. They may have already been removed.")
            else:
                 # This case (no successes, no failures reported) shouldn't usually happen if selection was valid
                 messagebox.showinfo("Deletion Info", "No password entries were deleted. They might have already been removed.")

            self.refresh_password_list() # Update the view regardless

        # Find delete button to show loading
        delete_button = self.dashboard_frame.winfo_children()[3].winfo_children()[2] # Fragile
        self.show_loading(delete_button, perform_delete, "🗑️ Delete Selected")


# --- Main Execution ---
if __name__ == "__main__":
    try:
        root = tk.Tk()
        # Set a minimum size for the window
        root.minsize(700, 500)
        app = PasswordManagerApp(root)
        root.mainloop()
    except Exception as e:
        # Catch unexpected errors during initialization or runtime
        import traceback
        messagebox.showerror("Fatal Error", f"An unexpected error occurred:\n{e}\n\n{traceback.format_exc()}")
        print(f"FATAL ERROR: {e}")
        traceback.print_exc()