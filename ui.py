import tkinter as tk
from tkinter import messagebox, ttk, simpledialog, Text
import re
import random
import string # For password generation
import time
import base64
import os
import threading
import traceback
import pyperclip # For clipboard management

try:
    from PIL import Image, ImageTk
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    print("Pillow (PIL) library not found. Graphical icons will not be loaded.")

# Adjusted import for clarity if firebase_service.py is in the same directory
from firebase_service import FirebaseService
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


# --- Encryption Utilities ---
def derive_encryption_key(master_password: str, salt_b64: str) -> bytes:
    if not master_password or not salt_b64:
        raise ValueError("Master password and salt are required for key derivation.")
    salt_bytes = base64.urlsafe_b64decode(salt_b64.encode('utf-8'))
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt_bytes,
        iterations=390000, # Standard iteration count
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
        if plain_text_data is None: return "" # Encrypt None as empty string
        if not isinstance(plain_text_data, str):
            plain_text_data = str(plain_text_data)
        return self.fernet.encrypt(plain_text_data.encode('utf-8')).decode('utf-8')

    def decrypt(self, encrypted_data_str: str) -> str:
        if not encrypted_data_str: return ""
        try:
            return self.fernet.decrypt(encrypted_data_str.encode('utf-8')).decode('utf-8')
        except InvalidToken:
            print("Decryption failed: Invalid token or key (InvalidToken).")
            raise # Re-raise to be caught by calling function
        except Exception as e:
            print(f"An unexpected error occurred during decryption: {e}")
            raise


class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager Pro (Firebase Secure Vault)")
        self.root.geometry("1100x800") # Slightly larger for new fields
        self.root.configure(bg="#e8ecef")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.firebase_service = FirebaseService(credentials_path="serviceAccountKey.json")
        if not self.firebase_service.db:
            messagebox.showerror("Startup Error",
                                 "Failed to connect to Firebase (see console for details). "
                                 "Application will not function correctly.")
            self.root.after(100, self.root.destroy)
            return

        # Color Scheme (can be customized further)
        self.primary_color = "#4a90e2"  # A modern blue
        self.secondary_color = "#357abd" # Darker blue for active states
        self.accent_color = "#b8d8f9"   # Lighter blue for accents/borders
        self.bg_color = "#f0f4f8"       # Light grayish blue background
        self.text_color = "#333333"     # Dark gray for text
        self.error_color = "#d9534f"    # Soft red for errors
        self.success_color = "#5cb85c"  # Soft green for success
        self.warning_color = "#f0ad4e"  # Soft orange for warnings
        self.entry_bg_color = "#ffffff"
        self.entry_fg_color = self.text_color
        self.button_text_color = "white"

        self.icons = {}
        self._load_icons() # Load textual icons

        self.configure_styles()

        self.current_user = None # Stores {'uid', 'email', 'idToken', 'refreshToken', 'displayName', 'encryptionSalt', 'passwordHint', 'accountRecoveryEmail'}
        self.encryption_service = None
        self.editing_credential_id = None # Stores the ID of the credential being edited
        self.form_history = []
        self.is_loading = False
        self.clipboard_clear_timer = None

        # Form Creation
        self.create_login_form()
        self.create_register_form()
        self.create_recovery_form()
        self.create_dashboard()
        self.create_edit_profile_form()
        self.create_add_credential_form()
        self.create_edit_credential_form()

        self.show_form("login")
        if hasattr(self, 'login_email_entry') and self.login_email_entry.winfo_exists():
            self.login_email_entry.focus_set()

    def _load_icons(self):
        # Using simple text icons for broad compatibility
        self.icons['add'] = "➕"
        self.icons['edit'] = "✏️"
        self.icons['delete'] = "🗑️"
        self.icons['back'] = "⬅️"
        self.icons['profile'] = "👤"
        self.icons['logout'] = "🚪"
        self.icons['search'] = "🔍"
        self.icons['clear'] = "❌"
        self.icons['login'] = "🔑"
        self.icons['register'] = "📝"
        self.icons['recover'] = "❓"
        self.icons['save'] = "💾"
        self.icons['show'] = "👁️"
        self.icons['hide'] = "👁‍🗨" # Alternative hide icon
        self.icons['generate'] = "⚙️"
        self.icons['copy'] = "📋"


    def configure_styles(self):
        self.style = ttk.Style()
        self.style.theme_use('clam') # A good base theme

        self.style.configure('TFrame', background=self.bg_color)
        self.style.configure('TLabel', background=self.bg_color, foreground=self.text_color, font=('Segoe UI', 11))
        self.style.configure('Title.TLabel', font=('Segoe UI', 24, 'bold'), foreground=self.primary_color, padding=(0, 15, 0, 15))
        self.style.configure('Header.TFrame', background=self.bg_color)
        self.style.configure('Form.TFrame', background=self.bg_color)

        self.style.configure('TButton', font=('Segoe UI', 11, 'bold'), borderwidth=1, padding=10, relief='raised', foreground=self.text_color, background=self.accent_color)
        self.style.map('TButton',
                       foreground=[('!active', self.text_color), ('active', self.text_color), ('disabled', '#a0a0a0')],
                       background=[('!active', self.accent_color), ('active', self.secondary_color), ('disabled', '#d0d0d0')],
                       relief=[('pressed', 'sunken'), ('!pressed', 'raised')])

        self.style.configure('Primary.TButton', background=self.primary_color, foreground=self.button_text_color)
        self.style.map('Primary.TButton', background=[('active', self.secondary_color), ('disabled', '#b0c4de')])

        self.style.configure('Secondary.TButton', background=self.secondary_color, foreground=self.button_text_color)
        self.style.map('Secondary.TButton', background=[('active', self.primary_color), ('disabled', '#c0d0e0')])

        self.style.configure('Danger.TButton', background=self.error_color, foreground=self.button_text_color)
        self.style.map('Danger.TButton', background=[('active', '#c53030'), ('disabled', '#f0b0b0')])

        self.style.configure('TEntry', fieldbackground=self.entry_bg_color, foreground=self.entry_fg_color, padding=8, relief='solid', borderwidth=1, bordercolor=self.accent_color, font=('Segoe UI', 10))
        self.style.map('TEntry', bordercolor=[('focus', self.primary_color), ('!focus', self.accent_color)],
                       fieldbackground=[('disabled', self.bg_color)])
        self.style.configure('Error.TEntry', fieldbackground='#fee2e2', bordercolor=self.error_color, foreground=self.error_color)

        self.style.configure('TCheckbutton', background=self.bg_color, foreground=self.text_color, font=('Segoe UI', 10))
        self.style.map('TCheckbutton', indicatorcolor=[('selected', self.primary_color), ('!selected', self.entry_bg_color)],
                       foreground=[('active', self.primary_color)])

        self.style.configure('Treeview', background=self.entry_bg_color, fieldbackground=self.entry_bg_color, foreground=self.text_color, font=('Segoe UI', 10), rowheight=30, relief='solid', borderwidth=1)
        self.style.configure('Treeview.Heading', background=self.primary_color, foreground='white', font=('Segoe UI', 11, 'bold'), padding=(10, 8), relief='flat')
        self.style.map('Treeview.Heading', relief=[('active','groove'), ('!active', 'flat')])
        self.style.map('Treeview', background=[('selected', self.secondary_color)], foreground=[('selected', 'white')])

        self.style.configure('Vertical.TScrollbar', background=self.primary_color, troughcolor=self.bg_color, bordercolor=self.primary_color, arrowcolor='white')
        self.style.map('Vertical.TScrollbar', background=[('active', self.secondary_color)])

        self.style.configure("info_row.Treeview", foreground="gray")
        self.style.configure("info_row_error.Treeview", foreground=self.error_color)
        self.style.configure("info_row_decrypt_error.Treeview", foreground=self.warning_color, font=('Segoe UI', 10, 'italic'))
        
        self.text_widget_options = {
            "font": ('Segoe UI', 10),
            "relief": tk.SOLID,
            "borderwidth": 1,
            "padx": 5,
            "pady": 5,
            "highlightthickness": 1,
            "highlightcolor": self.primary_color,
            "highlightbackground": self.accent_color,
            "bg": self.entry_bg_color,
            "fg": self.entry_fg_color,
        }


    def on_closing(self):
        if messagebox.askokcancel("Quit", "Do you want to quit Password Manager Pro?"):
            self.clear_clipboard_immediately()
            if self.clipboard_clear_timer:
                self.root.after_cancel(self.clipboard_clear_timer)
            self.current_user = None
            self.encryption_service = None
            if self.root and self.root.winfo_exists():
                 self.root.destroy()

    def _execute_operation_in_thread(self, operation_func_wrapped, original_button_text, button, callback_success=None, callback_failure=None):
        try:
            result = operation_func_wrapped()
            if callback_success and self.root.winfo_exists():
                self.root.after(0, callback_success, result)
        except Exception as e:
            print(f"Error in threaded operation {operation_func_wrapped.__name__ if hasattr(operation_func_wrapped, '__name__') else 'wrapped_operation'}: {e}")
            traceback.print_exc()
            if callback_failure and self.root.winfo_exists():
                self.root.after(0, callback_failure, e)
            elif self.root.winfo_exists():
                self.root.after(0, messagebox.showerror, "Operation Failed", f"An unexpected error occurred: {e}")
        finally:
            def final_ui_updates():
                if button and button.winfo_exists():
                    button.configure(state='normal', text=original_button_text)
                if self.root.winfo_exists():
                    self.root.config(cursor="")
                self.is_loading = False
            if self.root.winfo_exists():
                 self.root.after(0, final_ui_updates)
            else:
                 self.is_loading = False


    def show_loading_threaded(self, button, operation_func, original_text, op_args=None, op_kwargs=None, callback_success=None, callback_failure=None):
        if self.is_loading: return
        if not self.firebase_service.db and operation_func.__name__ not in ['_perform_login_operation', '_perform_register_operation', '_perform_recovery_operation']:
            messagebox.showerror("Database Error", "Firebase is not connected. Operation cannot be performed.")
            return

        self.is_loading = True
        if button and button.winfo_exists(): button.configure(state='disabled', text="Processing...")
        if self.root.winfo_exists(): self.root.config(cursor="wait"); self.root.update_idletasks()

        actual_op_args = op_args if op_args is not None else ()
        actual_op_kwargs = op_kwargs if op_kwargs is not None else {}

        def wrapped_operation():
            return operation_func(*actual_op_args, **actual_op_kwargs)

        thread_args = (wrapped_operation, original_text, button, callback_success, callback_failure)
        thread = threading.Thread(target=self._execute_operation_in_thread, args=thread_args)
        thread.daemon = True
        thread.start()

    def show_form(self, form_name):
        valid_forms = ["login", "register", "recover", "dashboard", "edit_profile", "add_credential", "edit_credential"]
        if form_name not in valid_forms:
            print(f"Error: Attempted to show invalid form '{form_name}'")
            return

        if not self.firebase_service.db and form_name not in ["login", "register", "recover"]:
             messagebox.showerror("Database Error", "Firebase is not connected. Cannot access this page.")
             if self.current_user: self.logout(silent=True)
             self.show_form("login")
             return

        if not self.form_history or self.form_history[-1] != form_name:
            self.form_history.append(form_name)

        for frame_attr_name in ["login_frame", "register_frame", "recover_frame",
                                "dashboard_frame", "edit_profile_frame",
                                "add_credential_frame", "edit_credential_frame"]:
            frame = getattr(self, frame_attr_name, None)
            if frame and frame.winfo_exists():
                frame.pack_forget()

        target_frame = getattr(self, f"{form_name}_frame")
        target_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=30)

        if form_name == "login" and hasattr(self,'login_email_entry'): self.login_email_entry.focus_set()
        elif form_name == "register" and hasattr(self,'register_display_name_entry'): self.register_display_name_entry.focus_set()
        elif form_name == "recover" and hasattr(self,'recovery_email_entry'): self.recovery_email_entry.focus_set()
        elif form_name == "dashboard":
            if self.current_user and self.encryption_service:
                self.refresh_credential_list()
            elif hasattr(self, 'credential_tree') and self.credential_tree.winfo_exists():
                for item in self.credential_tree.get_children(): self.credential_tree.delete(item)
                if not self.credential_tree.exists("INFO_NO_LOGIN_DASH"):
                    self.credential_tree.insert('', tk.END, iid="INFO_NO_LOGIN_DASH", values=("", "Please log in to view credentials.", "", "", ""), tags=("info_row",))
            if hasattr(self, 'search_entry'): self.search_entry.focus_set()
        elif form_name == "edit_profile" and hasattr(self,'edit_display_name_entry'):
            self.load_profile_data()
            self.edit_display_name_entry.focus_set()
        elif form_name == "add_credential" and hasattr(self,'add_service_name_entry'):
            self.add_service_name_entry.focus_set()
        elif form_name == "edit_credential" and hasattr(self,'edit_service_name_entry'):
            self.edit_service_name_entry.focus_set()


    def go_back(self):
        self.clear_clipboard_immediately()
        if len(self.form_history) > 1:
            self.form_history.pop()
            previous_form = self.form_history[-1]
            self.form_history.pop()
            self.show_form(previous_form)
        elif len(self.form_history) == 1 and self.form_history[0] != "login":
             self.form_history.pop()
             self.show_form("login")

    # --- Clipboard Utilities ---
    def copy_to_clipboard(self, text_to_copy, field_name="Password"):
        if not text_to_copy:
            messagebox.showinfo("Clipboard", f"{field_name} is empty, nothing to copy.")
            return
        try:
            pyperclip.copy(text_to_copy)
            messagebox.showinfo("Clipboard", f"{field_name} copied to clipboard. It will be cleared in 30 seconds.")
            self.schedule_clipboard_clear()
        except pyperclip.PyperclipException as e:
            messagebox.showerror("Clipboard Error", f"Could not copy to clipboard: {e}\nMake sure you have a copy/paste mechanism installed (e.g., xclip or xsel on Linux).")
        except Exception as e:
            messagebox.showerror("Clipboard Error", f"An unexpected error occurred with clipboard: {e}")


    def schedule_clipboard_clear(self, delay_ms=30000):
        if self.clipboard_clear_timer:
            self.root.after_cancel(self.clipboard_clear_timer)
        self.clipboard_clear_timer = self.root.after(delay_ms, self.clear_clipboard_with_message)

    def clear_clipboard_with_message(self):
        try:
            pyperclip.copy('')
            print("Clipboard cleared automatically.")
        except pyperclip.PyperclipException:
            pass
        except Exception:
            pass
        self.clipboard_clear_timer = None

    def clear_clipboard_immediately(self):
        if self.clipboard_clear_timer:
            self.root.after_cancel(self.clipboard_clear_timer)
            self.clipboard_clear_timer = None
        try:
            pyperclip.copy('')
            print("Clipboard cleared immediately.")
        except pyperclip.PyperclipException:
            pass
        except Exception:
            pass

    # --- Password Generation ---
    def generate_strong_password(self, length=16, use_uppercase=True, use_lowercase=True, use_digits=True, use_symbols=True):
        characters = ""
        if use_lowercase: characters += string.ascii_lowercase
        if use_uppercase: characters += string.ascii_uppercase
        if use_digits: characters += string.digits
        if use_symbols: characters += string.punctuation

        if not characters:
            messagebox.showerror("Password Generation Error", "No character types selected for password generation.")
            return ""

        password = ''.join(random.choice(characters) for i in range(length))
        return password

    def _populate_password_field(self, password_var, password_entry_widget):
        new_password = self.generate_strong_password()
        if new_password:
            password_var.set(new_password)
            is_hidden = password_entry_widget.cget('show') == "•"
            if is_hidden:
                password_entry_widget.config(show="")
                self.root.after(2000, lambda: password_entry_widget.config(show="•"))


    # --- FORM CREATION ---
    def create_login_form(self):
        self.login_frame = ttk.Frame(self.root, style='TFrame', name='login_frame')
        self.login_frame.columnconfigure(0, weight=1)
        header = ttk.Frame(self.login_frame, style='Header.TFrame'); header.grid(row=0, column=0, pady=(60, 30), sticky="ew"); header.columnconfigure(0, weight=1)
        ttk.Label(header, text=f"{self.icons['login']} Login to Your Vault", style='Title.TLabel').grid(row=0, column=0)
        form = ttk.Frame(self.login_frame, style='Form.TFrame', width=400); form.grid(row=1, column=0, padx=20, pady=10, sticky="n"); form.columnconfigure(0, weight=1); form.columnconfigure(1, weight=0)
        
        ttk.Label(form, text="Email").grid(row=0, column=0, columnspan=2, sticky="w", pady=(10, 2))
        self.login_email_var = tk.StringVar()
        self.login_email_entry = ttk.Entry(form, textvariable=self.login_email_var, width=45, font=('Segoe UI', 11))
        self.login_email_entry.grid(row=1, column=0, columnspan=2, sticky="ew", pady=5, ipady=2)
        self.login_email_entry.bind("<KeyRelease>", lambda e: self.validate_field(self.login_email_var, self.login_email_entry, 'email'))
        self.login_email_entry.bind("<Return>", lambda e: self.login_password_entry.focus_set())
        
        ttk.Label(form, text="Master Password").grid(row=2, column=0, columnspan=2, sticky="w", pady=(10, 2))
        self.login_password_var = tk.StringVar()
        self.login_password_entry = ttk.Entry(form, textvariable=self.login_password_var, show="•", width=40, font=('Segoe UI', 11))
        self.login_password_entry.grid(row=3, column=0, sticky="ew", pady=5, ipady=2)
        
        self.login_show_password_var = tk.BooleanVar(value=False)
        self.login_show_password_cb = ttk.Checkbutton(form, text="Show", variable=self.login_show_password_var, command=lambda: self.toggle_password_visibility(self.login_password_entry, self.login_show_password_var))
        self.login_show_password_cb.grid(row=3, column=1, padx=(10,0), sticky='w')
        self.login_password_entry.bind("<Return>", lambda e: self.login())
        
        self.login_button = ttk.Button(form, text="Login", style='Primary.TButton', command=self.login, width=18)
        self.login_button.grid(row=4, column=0, columnspan=2, pady=(30, 15), ipady=5)
        
        link_frame = ttk.Frame(form, style='Form.TFrame'); link_frame.grid(row=5, column=0, columnspan=2, pady=(10, 20), sticky="ew"); link_frame.columnconfigure(0, weight=1); link_frame.columnconfigure(1, weight=1)
        reg_button = ttk.Button(link_frame, text="Register New Account", style='TButton', command=lambda: self.show_form("register")); reg_button.grid(row=0, column=0, sticky="ew", padx=5)
        rec_button = ttk.Button(link_frame, text="Forgot Password?", style='TButton', command=lambda: self.show_form("recover")); rec_button.grid(row=0, column=1, sticky="ew", padx=5)

    def create_register_form(self):
        self.register_frame = ttk.Frame(self.root, style='TFrame', name='register_frame'); self.register_frame.columnconfigure(0, weight=1)
        header = ttk.Frame(self.register_frame, style='Header.TFrame'); header.grid(row=0, column=0, pady=(40,20), sticky="ew"); header.columnconfigure(0, weight=1)
        ttk.Label(header, text=f"{self.icons['register']} Create Your Secure Vault", style='Title.TLabel').pack(side=tk.LEFT, padx=20)
        ttk.Button(header, text=f"{self.icons['back']} Back to Login", style='Secondary.TButton', command=self.go_back).pack(side=tk.RIGHT, padx=20)
        
        form = ttk.Frame(self.register_frame, style='Form.TFrame', width=450); form.grid(row=1, column=0, padx=20, pady=10, sticky="n"); form.columnconfigure(0, weight=1); form.columnconfigure(1, weight=0)
        
        self.register_display_name_var = tk.StringVar()
        self.register_email_var = tk.StringVar()
        self.register_password_var = tk.StringVar()
        self.register_show_password_var = tk.BooleanVar(value=False)
        self.register_password_hint_var = tk.StringVar()
        self.register_account_recovery_email_var = tk.StringVar()

        row_idx = 0
        ttk.Label(form, text="Full Name / Display Name*").grid(row=row_idx, column=0, columnspan=2, sticky="w", pady=(10,2)); row_idx+=1
        self.register_display_name_entry = ttk.Entry(form, textvariable=self.register_display_name_var, width=50, font=('Segoe UI', 10))
        self.register_display_name_entry.grid(row=row_idx, column=0, columnspan=2, sticky="ew", pady=5, ipady=2)
        self.register_display_name_entry.bind("<KeyRelease>", lambda e: self.validate_field(self.register_display_name_var, self.register_display_name_entry, 'non_empty'))
        self.register_display_name_entry.bind("<Return>", lambda e: self.register_email_entry.focus_set()); row_idx+=1
        
        ttk.Label(form, text="Email Address (for login)*").grid(row=row_idx, column=0, columnspan=2, sticky="w", pady=(10,2)); row_idx+=1
        self.register_email_entry = ttk.Entry(form, textvariable=self.register_email_var, width=50, font=('Segoe UI', 10))
        self.register_email_entry.grid(row=row_idx, column=0, columnspan=2, sticky="ew", pady=5, ipady=2)
        self.register_email_entry.bind("<KeyRelease>", lambda e: self.validate_field(self.register_email_var, self.register_email_entry, 'email'))
        self.register_email_entry.bind("<Return>", lambda e: self.register_password_entry.focus_set()); row_idx+=1
        
        ttk.Label(form, text="Choose a Strong Master Password*").grid(row=row_idx, column=0, columnspan=2, sticky="w", pady=(10,2)); row_idx+=1
        self.register_password_entry = ttk.Entry(form, textvariable=self.register_password_var, show="•", width=45, font=('Segoe UI', 10))
        self.register_password_entry.grid(row=row_idx, column=0, sticky="ew", pady=5, ipady=2)
        self.register_show_password_cb = ttk.Checkbutton(form, text="Show", variable=self.register_show_password_var, command=lambda: self.toggle_password_visibility(self.register_password_entry, self.register_show_password_var))
        self.register_show_password_cb.grid(row=row_idx, column=1, padx=(10,0), sticky='w')
        self.register_password_entry.bind("<KeyRelease>", lambda e: self.validate_password_strength(self.register_password_var, self.register_password_entry, self.password_strength_bar, self.password_strength_label))
        self.register_password_entry.bind("<Return>", lambda e: self.register_password_hint_entry.focus_set()); row_idx+=1
        
        self.password_strength_frame = ttk.Frame(form, style='Form.TFrame'); self.password_strength_frame.grid(row=row_idx, column=0, columnspan=2, sticky="ew", pady=(0,10)); self.password_strength_frame.columnconfigure(0, weight=3); self.password_strength_frame.columnconfigure(1, weight=1)
        self.password_strength_bar = ttk.Progressbar(self.password_strength_frame, orient='horizontal', length=200, mode='determinate', value=0)
        self.password_strength_bar.grid(row=0, column=0, sticky='ew', padx=(0,5))
        self.password_strength_label = ttk.Label(self.password_strength_frame, text="Strength: -", font=('Segoe UI', 9)); self.password_strength_label.grid(row=0, column=1, sticky='w'); row_idx+=1

        ttk.Label(form, text="Master Password Hint (Optional, NEVER your actual password)").grid(row=row_idx, column=0, columnspan=2, sticky="w", pady=(10,2)); row_idx+=1
        self.register_password_hint_entry = ttk.Entry(form, textvariable=self.register_password_hint_var, width=50, font=('Segoe UI', 10))
        self.register_password_hint_entry.grid(row=row_idx, column=0, columnspan=2, sticky="ew", pady=5, ipady=2)
        self.register_password_hint_entry.bind("<Return>", lambda e: self.register_account_recovery_email_entry.focus_set()); row_idx+=1

        ttk.Label(form, text="Account Recovery Email (Optional, for Firebase account issues)").grid(row=row_idx, column=0, columnspan=2, sticky="w", pady=(10,2)); row_idx+=1
        self.register_account_recovery_email_entry = ttk.Entry(form, textvariable=self.register_account_recovery_email_var, width=50, font=('Segoe UI', 10))
        self.register_account_recovery_email_entry.grid(row=row_idx, column=0, columnspan=2, sticky="ew", pady=5, ipady=2)
        self.register_account_recovery_email_entry.bind("<KeyRelease>", lambda e: self.validate_field(self.register_account_recovery_email_var, self.register_account_recovery_email_entry, 'email_optional'))
        self.register_account_recovery_email_entry.bind("<Return>", lambda e: self.register()); row_idx+=1
        
        self.register_button = ttk.Button(form, text="Register", style='Primary.TButton', command=self.register, width=18)
        self.register_button.grid(row=row_idx, column=0, columnspan=2, pady=(25,10), ipady=5)

    def create_recovery_form(self):
        self.recover_frame = ttk.Frame(self.root, style='TFrame', name='recover_frame'); self.recover_frame.columnconfigure(0, weight=1)
        header = ttk.Frame(self.recover_frame, style='Header.TFrame'); header.grid(row=0, column=0, pady=(60,30), sticky="ew"); header.columnconfigure(0, weight=1)
        ttk.Label(header, text=f"{self.icons['recover']} Recover Master Password", style='Title.TLabel').pack(side=tk.LEFT, padx=20)
        ttk.Button(header, text=f"{self.icons['back']} Back to Login", style='Secondary.TButton', command=self.go_back).pack(side=tk.RIGHT, padx=20)
        
        form = ttk.Frame(self.recover_frame, style='Form.TFrame', width=450); form.grid(row=1, column=0, padx=20, pady=10, sticky="n"); form.columnconfigure(0, weight=1)
        ttk.Label(form, text="Enter your registered Login Email:").grid(row=0, column=0, sticky="w", pady=(10,2))
        self.recovery_email_var = tk.StringVar()
        self.recovery_email_entry = ttk.Entry(form, textvariable=self.recovery_email_var, width=50, font=('Segoe UI', 10))
        self.recovery_email_entry.grid(row=1, column=0, sticky="ew", pady=5, ipady=2)
        self.recovery_email_entry.bind("<KeyRelease>", lambda e: self.validate_field(self.recovery_email_var, self.recovery_email_entry, 'email'))
        self.recovery_email_entry.bind("<Return>", lambda e: self.recover_account())
        
        self.recover_button = ttk.Button(form, text="Send Recovery Email", style='Primary.TButton', command=self.recover_account, width=25)
        self.recover_button.grid(row=2, column=0, pady=(30,10), ipady=5)
        ttk.Label(form, text="If an account exists with this email, a password reset link will be sent by Firebase.", justify=tk.CENTER, font=('Segoe UI', 9)).grid(row=3, column=0, pady=(20,0))

    def create_dashboard(self):
        self.dashboard_frame = ttk.Frame(self.root, style='TFrame', name='dashboard_frame'); self.dashboard_frame.columnconfigure(0, weight=1); self.dashboard_frame.rowconfigure(2, weight=1)
        
        header = ttk.Frame(self.dashboard_frame, style='Header.TFrame'); header.grid(row=0, column=0, pady=(20,15), sticky="ew", padx=10); header.columnconfigure(0, weight=1)
        self.welcome_label = ttk.Label(header, text="🔐 Your Secure Credentials", style='Title.TLabel'); self.welcome_label.grid(row=0, column=0, sticky='w')
        profile_button = ttk.Button(header, text=f"{self.icons['profile']} Profile", style='Secondary.TButton', command=lambda: self.show_form("edit_profile")); profile_button.grid(row=0, column=1, sticky="e", padx=5)
        logout_button = ttk.Button(header, text=f"{self.icons['logout']} Logout", style='Danger.TButton', command=self.logout); logout_button.grid(row=0, column=2, sticky="e", padx=5)
        
        toolbar = ttk.Frame(self.dashboard_frame, style='Form.TFrame'); toolbar.grid(row=1, column=0, pady=10, sticky="ew", padx=10); toolbar.columnconfigure(0, weight=1)
        self.search_entry_var = tk.StringVar()
        self.search_entry = ttk.Entry(toolbar, textvariable=self.search_entry_var, width=60, font=('Segoe UI', 10))
        self.search_entry.grid(row=0, column=0, padx=(0,5), sticky="ew", ipady=2)
        self.search_entry.bind("<KeyRelease>", lambda e: self.search_credentials())
        search_button = ttk.Button(toolbar, text=f"{self.icons['search']} Search", style='Secondary.TButton', command=self.search_credentials); search_button.grid(row=0, column=1, padx=5)
        clear_button = ttk.Button(toolbar, text=f"{self.icons['clear']} Clear", style='TButton', command=self.clear_search); clear_button.grid(row=0, column=2, padx=5)
        
        tree_frame = ttk.Frame(self.dashboard_frame, style='TFrame'); tree_frame.grid(row=2, column=0, sticky="nsew", padx=10, pady=(0,10)); tree_frame.columnconfigure(0, weight=1); tree_frame.rowconfigure(0, weight=1)
        self.credential_tree = ttk.Treeview(tree_frame, columns=('ID', 'ServiceName', 'LoginID', 'Website', 'Tags'), show='headings', style='Treeview', name="credential_tree")
        self.credential_tree.heading('ID', text='ID'); self.credential_tree.heading('ServiceName', text='Service Name'); self.credential_tree.heading('LoginID', text='Login ID'); self.credential_tree.heading('Website', text='Website'); self.credential_tree.heading('Tags', text='Tags')
        self.credential_tree.column('ID', width=0, stretch=tk.NO); 
        self.credential_tree.column('ServiceName', width=200, anchor='w'); self.credential_tree.column('LoginID', width=200, anchor='w'); self.credential_tree.column('Website', width=250, anchor='w'); self.credential_tree.column('Tags', width=150, anchor='w')
        self.credential_tree.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.credential_tree.yview, style='Vertical.TScrollbar'); scrollbar.grid(row=0, column=1, sticky="ns"); self.credential_tree.configure(yscrollcommand=scrollbar.set)
        self.credential_tree.bind("<Double-1>", lambda e: self.edit_selected_credential())
        self.credential_tree.bind("<Button-3>", self.show_credential_context_menu)

        buttons_frame = ttk.Frame(self.dashboard_frame, style='Form.TFrame'); buttons_frame.grid(row=3, column=0, pady=(15,10), sticky="ew", padx=10)
        buttons_frame.columnconfigure(0, weight=1); buttons_frame.columnconfigure(1, weight=1); buttons_frame.columnconfigure(2, weight=1); buttons_frame.columnconfigure(3, weight=1)
        
        add_button = ttk.Button(buttons_frame, text=f"{self.icons['add']} Add New", style='Primary.TButton', command=lambda: self.show_form("add_credential")); add_button.grid(row=0, column=0, padx=5, sticky='ew', ipady=3)
        self.dashboard_edit_button = ttk.Button(buttons_frame, text=f"{self.icons['edit']} View/Edit", style='Secondary.TButton', command=self.edit_selected_credential); self.dashboard_edit_button.grid(row=0, column=1, padx=5, sticky='ew', ipady=3)
        self.dashboard_copy_button = ttk.Button(buttons_frame, text=f"{self.icons['copy']} Copy Pwd", style='TButton', command=self.copy_selected_password); self.dashboard_copy_button.grid(row=0, column=2, padx=5, sticky='ew', ipady=3)
        self.dashboard_delete_button = ttk.Button(buttons_frame, text=f"{self.icons['delete']} Delete", style='Danger.TButton', command=self.delete_credential); self.dashboard_delete_button.grid(row=0, column=3, padx=5, sticky='ew', ipady=3)

    def show_credential_context_menu(self, event):
        selected_item_id = self.credential_tree.identify_row(event.y)
        if not selected_item_id or selected_item_id.startswith("INFO_"):
            return

        self.credential_tree.selection_set(selected_item_id)

        context_menu = tk.Menu(self.credential_tree, tearoff=0)
        context_menu.add_command(label=f"{self.icons['edit']} View/Edit Entry", command=self.edit_selected_credential)
        context_menu.add_command(label=f"{self.icons['copy']} Copy Password", command=self.copy_selected_password)
        context_menu.add_command(label=f"{self.icons['copy']} Copy Login ID", command=self.copy_selected_login_id)
        context_menu.add_separator()
        context_menu.add_command(label=f"{self.icons['delete']} Delete Entry", command=self.delete_credential)
        
        context_menu.tk_popup(event.x_root, event.y_root)

    def create_edit_profile_form(self):
        self.edit_profile_frame = ttk.Frame(self.root, style='TFrame', name='edit_profile_frame'); self.edit_profile_frame.columnconfigure(0, weight=1)
        header = ttk.Frame(self.edit_profile_frame, style='Header.TFrame'); header.grid(row=0, column=0, pady=(40,20), sticky="ew"); header.columnconfigure(0, weight=1)
        ttk.Label(header, text=f"{self.icons['profile']} Edit Your Profile", style='Title.TLabel').pack(side=tk.LEFT, padx=20)
        ttk.Button(header, text=f"{self.icons['back']} Back to Dashboard", style='Secondary.TButton', command=self.go_back).pack(side=tk.RIGHT, padx=20)
        
        form = ttk.Frame(self.edit_profile_frame, style='Form.TFrame', width=450); form.grid(row=1, column=0, padx=20, pady=10, sticky="n"); form.columnconfigure(0, weight=1); form.columnconfigure(1, weight=0)
        row_idx = 0
        
        ttk.Label(form, text="Display Name*").grid(row=row_idx, column=0, columnspan=2, sticky="w", pady=(10,2)); row_idx+=1
        self.edit_display_name_var = tk.StringVar()
        self.edit_display_name_entry = ttk.Entry(form, textvariable=self.edit_display_name_var, width=50, font=('Segoe UI', 10))
        self.edit_display_name_entry.grid(row=row_idx, column=0, columnspan=2, sticky="ew", pady=5, ipady=2); row_idx+=1
        
        ttk.Label(form, text="New Master Password (leave blank to keep current)").grid(row=row_idx, column=0, columnspan=2, sticky="w", pady=(10,2)); row_idx+=1
        self.edit_master_password_var = tk.StringVar()
        self.edit_master_password_entry = ttk.Entry(form, textvariable=self.edit_master_password_var, show="•", width=45, font=('Segoe UI', 10))
        self.edit_master_password_entry.grid(row=row_idx, column=0, sticky="ew", pady=5, ipady=2)
        self.edit_show_master_password_var = tk.BooleanVar(value=False)
        self.edit_show_master_password_cb = ttk.Checkbutton(form, text="Show", variable=self.edit_show_master_password_var, command=lambda: self.toggle_password_visibility(self.edit_master_password_entry, self.edit_show_master_password_var))
        self.edit_show_master_password_cb.grid(row=row_idx, column=1, padx=(10,0), sticky='w'); row_idx+=1
        
        ttk.Label(form, text="Master Password Hint (Optional, NEVER your actual password)").grid(row=row_idx, column=0, columnspan=2, sticky="w", pady=(10,2)); row_idx+=1
        self.edit_password_hint_var = tk.StringVar()
        self.edit_password_hint_entry = ttk.Entry(form, textvariable=self.edit_password_hint_var, width=50, font=('Segoe UI', 10))
        self.edit_password_hint_entry.grid(row=row_idx, column=0, columnspan=2, sticky="ew", pady=5, ipady=2); row_idx+=1

        ttk.Label(form, text="Account Recovery Email (Optional, for Firebase account matters)").grid(row=row_idx, column=0, columnspan=2, sticky="w", pady=(10,2)); row_idx+=1
        self.edit_account_recovery_email_var = tk.StringVar()
        self.edit_account_recovery_email_entry = ttk.Entry(form, textvariable=self.edit_account_recovery_email_var, width=50, font=('Segoe UI', 10))
        self.edit_account_recovery_email_entry.grid(row=row_idx, column=0, columnspan=2, sticky="ew", pady=5, ipady=2); row_idx+=1
        self.edit_account_recovery_email_entry.bind("<KeyRelease>", lambda e: self.validate_field(self.edit_account_recovery_email_var, self.edit_account_recovery_email_entry, 'email_optional'))
        
        buttons_frame = ttk.Frame(form, style='Form.TFrame'); buttons_frame.grid(row=row_idx, column=0, columnspan=2, pady=(30,10), sticky='ew'); buttons_frame.columnconfigure(0, weight=1)
        self.save_profile_button = ttk.Button(buttons_frame, text=f"{self.icons['save']} Save Profile", style='Primary.TButton', command=self.save_profile_changes)
        self.save_profile_button.grid(row=0, column=0, padx=5, sticky='ew', ipady=5)

    def create_credential_form_fields(self, parent_form, service_name_var, login_id_var, password_var, show_password_var, website_var, notes_text_widget_ref_name, tags_var, form_type="add"):
        row_idx = 0

        ttk.Label(parent_form, text="Service Name (e.g., Google, Netflix)*").grid(row=row_idx, column=0, columnspan=3, sticky="w", pady=(10,2)); row_idx+=1
        entry_widget = ttk.Entry(parent_form, textvariable=service_name_var, width=50, font=('Segoe UI', 10))
        entry_widget.grid(row=row_idx, column=0, columnspan=3, sticky="ew", pady=5, ipady=2); row_idx+=1
        if form_type == "add": self.add_service_name_entry = entry_widget
        else: self.edit_service_name_entry = entry_widget
        
        ttk.Label(parent_form, text="Login ID (Username, Email, etc.)*").grid(row=row_idx, column=0, columnspan=3, sticky="w", pady=(10,2)); row_idx+=1
        entry_widget = ttk.Entry(parent_form, textvariable=login_id_var, width=50, font=('Segoe UI', 10))
        entry_widget.grid(row=row_idx, column=0, columnspan=3, sticky="ew", pady=5, ipady=2); row_idx+=1
        if form_type == "add": self.add_login_id_entry = entry_widget
        else: self.edit_login_id_entry = entry_widget

        ttk.Label(parent_form, text="Password*").grid(row=row_idx, column=0, columnspan=3, sticky="w", pady=(10,2)); row_idx+=1
        password_entry = ttk.Entry(parent_form, textvariable=password_var, show="•", width=38, font=('Segoe UI', 10))
        password_entry.grid(row=row_idx, column=0, sticky="ew", pady=5, ipady=2)
        
        show_cb = ttk.Checkbutton(parent_form, text="Show", variable=show_password_var, command=lambda p=password_entry, v=show_password_var: self.toggle_password_visibility(p,v))
        show_cb.grid(row=row_idx, column=1, padx=(5,0), sticky='w')
        generate_button = ttk.Button(parent_form, text=self.icons['generate'], style='TButton', width=3, command=lambda pv=password_var, pe=password_entry: self._populate_password_field(pv,pe))
        generate_button.grid(row=row_idx, column=2, padx=(5,0), sticky='w')
        row_idx+=1
        if form_type == "add": self.add_password_entry = password_entry; self.add_show_password_var = show_password_var
        else: self.edit_password_entry = password_entry; self.edit_show_password_var = show_password_var

        ttk.Label(parent_form, text="Website URL (Optional)").grid(row=row_idx, column=0, columnspan=3, sticky="w", pady=(10,2)); row_idx+=1
        entry_widget = ttk.Entry(parent_form, textvariable=website_var, width=50, font=('Segoe UI', 10))
        entry_widget.grid(row=row_idx, column=0, columnspan=3, sticky="ew", pady=5, ipady=2); row_idx+=1
        if form_type == "add": self.add_website_entry = entry_widget
        else: self.edit_website_entry = entry_widget

        ttk.Label(parent_form, text="Notes (Optional)").grid(row=row_idx, column=0, columnspan=3, sticky="w", pady=(10,2)); row_idx+=1
        notes_text = Text(parent_form, width=50, height=5, **self.text_widget_options)
        notes_text.grid(row=row_idx, column=0, columnspan=3, sticky="ew", pady=5)
        notes_scrollbar = ttk.Scrollbar(parent_form, orient="vertical", command=notes_text.yview, style='Vertical.TScrollbar')
        notes_scrollbar.grid(row=row_idx, column=3, sticky="ns", pady=5, padx=(0,5))
        notes_text.configure(yscrollcommand=notes_scrollbar.set)
        row_idx+=1
        setattr(self, notes_text_widget_ref_name, notes_text)


        ttk.Label(parent_form, text="Tags (Optional, comma-separated, e.g., work,social,finance)").grid(row=row_idx, column=0, columnspan=3, sticky="w", pady=(10,2)); row_idx+=1
        entry_widget = ttk.Entry(parent_form, textvariable=tags_var, width=50, font=('Segoe UI', 10))
        entry_widget.grid(row=row_idx, column=0, columnspan=3, sticky="ew", pady=5, ipady=2); row_idx+=1
        if form_type == "add": self.add_tags_entry = entry_widget
        else: self.edit_tags_entry = entry_widget
        
        return row_idx


    def create_add_credential_form(self):
        self.add_credential_frame = ttk.Frame(self.root, style='TFrame', name='add_credential_frame'); self.add_credential_frame.columnconfigure(0, weight=1)
        header = ttk.Frame(self.add_credential_frame, style='Header.TFrame'); header.grid(row=0, column=0, pady=(40,20), sticky="ew"); header.columnconfigure(0, weight=1)
        ttk.Label(header, text=f"{self.icons['add']} Add New Credential", style='Title.TLabel').pack(side=tk.LEFT, padx=20)
        ttk.Button(header, text=f"{self.icons['back']} Back to Dashboard", style='Secondary.TButton', command=self.go_back).pack(side=tk.RIGHT, padx=20)
        
        form = ttk.Frame(self.add_credential_frame, style='Form.TFrame', width=500); form.grid(row=1, column=0, padx=20, pady=10, sticky="n")
        form.columnconfigure(0, weight=1); form.columnconfigure(1, weight=0); form.columnconfigure(2, weight=0)
        
        self.add_service_name_var = tk.StringVar()
        self.add_login_id_var = tk.StringVar()
        self.add_password_var = tk.StringVar()
        self.add_website_var = tk.StringVar()
        self.add_tags_var = tk.StringVar()

        row_idx = self.create_credential_form_fields(
            form, self.add_service_name_var, self.add_login_id_var, self.add_password_var, 
            tk.BooleanVar(value=False), self.add_website_var, "add_notes_text", self.add_tags_var, "add"
        )
        
        self.save_credential_button = ttk.Button(form, text=f"{self.icons['save']} Save Credential", style='Primary.TButton', command=self.save_new_credential, width=20)
        self.save_credential_button.grid(row=row_idx, column=0, columnspan=3, pady=(30,10), ipady=5)

    def create_edit_credential_form(self):
        self.edit_credential_frame = ttk.Frame(self.root, style='TFrame', name='edit_credential_frame'); self.edit_credential_frame.columnconfigure(0, weight=1)
        header = ttk.Frame(self.edit_credential_frame, style='Header.TFrame'); header.grid(row=0, column=0, pady=(40,20), sticky="ew"); header.columnconfigure(0, weight=1)
        ttk.Label(header, text=f"{self.icons['edit']} Edit Credential Entry", style='Title.TLabel').pack(side=tk.LEFT, padx=20)
        ttk.Button(header, text=f"{self.icons['back']} Back to Dashboard", style='Secondary.TButton', command=self.go_back).pack(side=tk.RIGHT, padx=20)

        form = ttk.Frame(self.edit_credential_frame, style='Form.TFrame', width=500); form.grid(row=1, column=0, padx=20, pady=10, sticky="n")
        form.columnconfigure(0, weight=1); form.columnconfigure(1, weight=0); form.columnconfigure(2, weight=0)
        
        self.edit_service_name_var = tk.StringVar()
        self.edit_login_id_var = tk.StringVar()
        self.edit_password_var = tk.StringVar()
        self.edit_website_var = tk.StringVar()
        self.edit_tags_var = tk.StringVar()

        row_idx = self.create_credential_form_fields(
            form, self.edit_service_name_var, self.edit_login_id_var, self.edit_password_var, 
            tk.BooleanVar(value=False), self.edit_website_var, "edit_notes_text", self.edit_tags_var, "edit"
        )
        
        self.save_edits_button = ttk.Button(form, text=f"{self.icons['save']} Save Changes", style='Primary.TButton', command=self.save_edited_credential, width=20)
        self.save_edits_button.grid(row=row_idx, column=0, columnspan=3, pady=(30,10), ipady=5)

    # --- Utility and Validation ---
    def toggle_password_visibility(self, entry_widget, show_var):
        if show_var.get():
            entry_widget.configure(show="")
        else:
            entry_widget.configure(show="•")

    def validate_field(self, string_var, entry_widget, validation_type='email'):
        value = string_var.get().strip()
        is_valid = True
        entry_widget.configure(style='TEntry')

        if validation_type == 'email':
            is_valid = self.validate_email_format(value) if value else False
        elif validation_type == 'email_optional':
            is_valid = self.validate_email_format(value) if value else True
        elif validation_type == 'non_empty':
            is_valid = bool(value)
        
        if not is_valid:
            entry_widget.configure(style='Error.TEntry')
        return is_valid

    def validate_password_strength(self, password_var, password_entry, strength_bar_widget, strength_label_widget):
        password = password_var.get()
        strength_score = 0
        label_text = "Strength: -"
        bar_color = self.text_color
        
        strength_bar_widget.configure(style='TProgressbar')
        strength_label_widget.configure(foreground=self.text_color)
        password_entry.configure(style='TEntry')


        if not password:
            strength_score = 0
            label_text = "Strength: -"
        else:
            criteria = {
                "length": len(password) >= 8,
                "uppercase": bool(re.search(r'[A-Z]', password)),
                "lowercase": bool(re.search(r'[a-z]', password)),
                "digit": bool(re.search(r'[0-9]', password)),
                "symbol": bool(re.search(r'[^A-Za-z0-9]', password))
            }
            met_criteria_count = sum(criteria.values())

            if len(password) < 8:
                strength_score = max(10, len(password) * 3)
                label_text = "Very Weak (min 8 chars)"
                bar_color = self.error_color
                entry_style_name = 'Error.TEntry'
            elif met_criteria_count <= 2:
                strength_score = max(25, len(password) * 5)
                label_text = "Weak"
                bar_color = self.error_color
                entry_style_name = 'Error.TEntry'
            elif met_criteria_count <= 4 :
                strength_score = 65
                label_text = "Medium"
                bar_color = self.warning_color
                entry_style_name = 'TEntry'
            else: 
                strength_score = 100
                label_text = "Strong"
                bar_color = self.success_color
                entry_style_name = 'TEntry'
            
            style_name = f'{label_text.split()[0]}.Horizontal.TProgressbar'
            self.style.configure(style_name, background=bar_color)
            strength_bar_widget.configure(style=style_name)
            password_entry.configure(style=entry_style_name)


        strength_bar_widget['value'] = strength_score
        strength_label_widget.configure(text=f"Strength: {label_text}", foreground=bar_color)


    def validate_email_format(self, email):
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

    # --- Authentication Logic ---
    def login(self):
        email = self.login_email_var.get().strip()
        plain_master_password = self.login_password_var.get()

        if not self.validate_field(self.login_email_var, self.login_email_entry, 'email'):
            messagebox.showerror("Login Error", "Invalid email format.")
            self.login_email_entry.focus_set()
            return
        if not plain_master_password:
            messagebox.showerror("Login Error", "Master Password cannot be empty.")
            self.login_password_entry.focus_set()
            return
        if not self.firebase_service.db:
            messagebox.showerror("Login Error", "Database service is not available. Cannot log in.")
            return

        op_args = (email, plain_master_password)
        self.show_loading_threaded(self.login_button, self._perform_login_operation, "Login",
                                   op_args=op_args,
                                   callback_success=self._login_success,
                                   callback_failure=self._login_failure)

    def _perform_login_operation(self, email, plain_master_password):
        auth_data, error = self.firebase_service.sign_in_user_auth(email, plain_master_password)
        if error: raise Exception(error)
        if not auth_data or 'localId' not in auth_data:
            raise Exception("Authentication failed or returned invalid data.")

        uid = auth_data['localId']
        user_profile = self.firebase_service.get_user_profile_by_uid(uid)
        if not user_profile or 'key_salt' not in user_profile: # CHECKING FOR 'key_salt'
            raise Exception("User profile incomplete or not found (missing encryption salt). Please contact support or try re-registering.")
        
        return {"auth_data": auth_data, "user_profile": user_profile, "plain_master_password": plain_master_password}

    def _login_success(self, result_data):
        auth_data = result_data['auth_data']
        user_profile = result_data['user_profile']
        plain_master_password = result_data['plain_master_password']

        self.current_user = {
            'uid': auth_data['localId'],
            'email': auth_data['email'],
            'idToken': auth_data['idToken'],
            'refreshToken': auth_data.get('refreshToken'),
            'displayName': user_profile.get('name', 'User'), # Use 'name' from service
            'encryptionSalt': user_profile['key_salt'], # CORRECTED to 'key_salt'
            'passwordHint': user_profile.get('passwordHint', ''), # Assuming service might add this field
            'accountRecoveryEmail': user_profile.get('recovery_email', auth_data['email']) # Use 'recovery_email'
        }
        try:
            print(f"Login Success: Deriving encryption key with master password (len: {len(plain_master_password)}) and salt: {self.current_user['encryptionSalt']}")
            derived_key = derive_encryption_key(plain_master_password, self.current_user['encryptionSalt'])
            self.encryption_service = EncryptionService(derived_key)
            print("Login Success: EncryptionService initialized.")
        except Exception as e:
            messagebox.showerror("Encryption Key Error", f"Could not prepare data encryption: {e}. Login aborted.")
            print(f"Login Failed: EncryptionService initialization error: {e}"); traceback.print_exc()
            self.current_user = None; self.encryption_service = None
            return

        self.update_welcome_message()
        self.show_form("dashboard")
        self.login_email_var.set("")
        self.login_password_var.set("")
        self.login_show_password_var.set(False)
        self.toggle_password_visibility(self.login_password_entry, self.login_show_password_var)
        messagebox.showinfo("Login Success", f"Welcome back, {self.current_user['displayName']}!")

    def _login_failure(self, error):
        messagebox.showerror("Login Failed", str(error))
        self.login_password_entry.focus_set()


    def register(self):
        display_name = self.register_display_name_var.get().strip()
        email = self.register_email_var.get().strip()
        plain_password = self.register_password_var.get()
        password_hint = self.register_password_hint_var.get().strip() # This will be passed as 'plain_pin' to service for profile
        account_recovery_email = self.register_account_recovery_email_var.get().strip()

        if not self.validate_field(self.register_display_name_var, self.register_display_name_entry, 'non_empty'):
            messagebox.showerror("Registration Error", "Display Name cannot be empty."); self.register_display_name_entry.focus_set(); return
        if not self.validate_field(self.register_email_var, self.register_email_entry, 'email'):
            messagebox.showerror("Registration Error", "Invalid Email Address format."); self.register_email_entry.focus_set(); return
        
        self.validate_password_strength(self.register_password_var, self.register_password_entry, self.password_strength_bar, self.password_strength_label)
        if len(plain_password) < 8:
            messagebox.showerror("Registration Error", "Master Password must be at least 8 characters long."); self.register_password_entry.focus_set(); return
        
        if account_recovery_email and not self.validate_email_format(account_recovery_email):
            messagebox.showerror("Registration Error", "Invalid format for Account Recovery Email."); self.register_account_recovery_email_entry.focus_set(); return
            
        if not self.firebase_service.db:
            messagebox.showerror("Registration Error", "Database service is unavailable. Cannot register."); return

        # For create_user_profile, password_hint maps to plain_pin (which is hashed)
        op_args = (display_name, email, plain_password, account_recovery_email, password_hint)
        self.show_loading_threaded(self.register_button, self._perform_register_operation, "Register",
                                   op_args=op_args,
                                   callback_success=self._register_success,
                                   callback_failure=self._register_failure)

    def _perform_register_operation(self, display_name, email, plain_password, account_recovery_email, password_hint_as_pin):
        auth_user_record, error = self.firebase_service.create_user_in_auth(email, plain_password, display_name)
        if error:
            if error == "exists":
                raise Exception("This email address is already registered. Please try logging in or use a different email.")
            raise Exception(f"Firebase Auth user creation failed: {error}")
        if not auth_user_record:
            raise Exception("Failed to create user in Firebase Authentication (no record returned).")

        profile_uid, profile_error = self.firebase_service.create_user_profile(
            auth_user_record.uid, 
            display_name, # name
            email, # email
            account_recovery_email, # recovery_email
            password_hint_as_pin # plain_pin (this will be hashed by the service for profile's pin_hash)
            # The service will also store the password_hint in the profile if that field name exists in create_user_profile's data.
            # For now, assuming password_hint from UI is used as the profile's PIN if desired.
            # If you want 'passwordHint' as a separate field in Firestore 'users' doc,
            # firebase_service.create_user_profile needs to be adjusted to take it and store it.
            # Currently, it seems the 'password_hint' from registration form is for the `pin_hash` in `users` collection.
        )
        if profile_error:
            raise Exception(f"Failed to create user profile in Firestore: {profile_error}")
        if not profile_uid:
            raise Exception("Failed to create user profile (no UID returned from profile creation).")
        
        return profile_uid

    def _register_success(self, result_uid):
        messagebox.showinfo("Registration Successful", "Your secure vault has been created! Please log in.")
        self.register_display_name_var.set("")
        self.register_email_var.set("")
        self.register_password_var.set("")
        self.register_password_hint_var.set("")
        self.register_account_recovery_email_var.set("")
        self.register_show_password_var.set(False)
        self.toggle_password_visibility(self.register_password_entry, self.register_show_password_var)
        self.validate_password_strength(self.register_password_var, self.register_password_entry, self.password_strength_bar, self.password_strength_label)
        self.show_form("login")

    def _register_failure(self, error):
        messagebox.showerror("Registration Failed", str(error))
        if "email address is already registered" in str(error) or "EMAIL_EXISTS" in str(error).upper():
            self.register_email_entry.focus_set()
            self.validate_field(self.register_email_var, self.register_email_entry, 'email')
        else:
            self.register_display_name_entry.focus_set()


    def recover_account(self):
        email_rec = self.recovery_email_var.get().strip()
        if not self.validate_field(self.recovery_email_var, self.recovery_email_entry, 'email'):
            messagebox.showerror("Recovery Error", "Invalid email format."); self.recovery_email_entry.focus_set(); return
        if not self.firebase_service.db:
            messagebox.showerror("Recovery Error", "Database service unavailable."); return

        op_args = (email_rec,)
        self.show_loading_threaded(self.recover_button, self._perform_recovery_operation, "Send Recovery Email",
                                   op_args=op_args,
                                   callback_success=self._recover_success,
                                   callback_failure=self._recover_failure)

    def _perform_recovery_operation(self, email_rec):
        success, message = self.firebase_service.send_password_reset_email_auth(email_rec)
        if not success:
            raise Exception(message)
        return message

    def _recover_success(self, message):
        messagebox.showinfo("Password Recovery", message)
        self.show_form("login")
        self.recovery_email_var.set("")

    def _recover_failure(self, error):
        messagebox.showerror("Recovery Failed", str(error))
        self.recovery_email_entry.focus_set()

    def logout(self, silent=False):
        self.clear_clipboard_immediately()
        confirm = True
        if not silent:
            confirm = messagebox.askyesno("Log Out", "Are you sure you want to log out securely?")
        
        if confirm:
            self.current_user = None
            self.encryption_service = None
            self.editing_credential_id = None
            self.form_history = []

            if hasattr(self, 'credential_tree') and self.credential_tree.winfo_exists():
                for item in self.credential_tree.get_children(): self.credential_tree.delete(item)
                if not self.credential_tree.exists("INFO_LOGGED_OUT"):
                    self.credential_tree.insert('', tk.END, iid="INFO_LOGGED_OUT", values=("", "Logged out. Please log in again.", "", "", ""), tags=("info_row",))
            
            if hasattr(self, 'search_entry_var') and hasattr(self.search_entry_var, 'set'):
                self.search_entry_var.set("")
            
            self.show_form("login")
            if not silent:
                messagebox.showinfo("Logged Out", "You have been successfully logged out.")

    def update_welcome_message(self):
        if self.current_user and hasattr(self, 'welcome_label') and self.welcome_label.winfo_exists():
            self.welcome_label.config(text=f"🔐 Welcome, {self.current_user.get('displayName', 'User')}!")
        elif hasattr(self, 'welcome_label') and self.welcome_label.winfo_exists():
            self.welcome_label.config(text="🔐 Your Secure Credentials")

    # --- Dashboard and Credential List ---
    def clear_search(self):
        if hasattr(self, 'search_entry_var') and hasattr(self.search_entry_var, 'set'):
            self.search_entry_var.set("")
        self.refresh_credential_list()
        if hasattr(self, 'search_entry') and self.search_entry.winfo_exists():
            self.search_entry.focus_set()

    def search_credentials(self):
        self.refresh_credential_list(search_term=self.search_entry_var.get().strip().lower())

    def refresh_credential_list(self, search_term=None):
        if not hasattr(self, 'credential_tree') or not self.credential_tree.winfo_exists(): return
        print(f"\n--- Refreshing credential list. Search term: '{search_term}' ---")
        for item in self.credential_tree.get_children(): self.credential_tree.delete(item)

        def _insert_info_message(iid, message, tag="info_row"):
            if self.credential_tree.winfo_exists() and not self.credential_tree.exists(iid):
                self.credential_tree.insert('', tk.END, iid=iid, values=("", message, "", "", ""), tags=(tag,))

        if not self.firebase_service.db:
            _insert_info_message("INFO_NO_DB_CONN", "Database not connected. Cannot load credentials.", "info_row_error"); return
        if not self.current_user:
            _insert_info_message("INFO_NO_LOGIN_REFRESH", "Not logged in. Please log in to view credentials.", "info_row"); return
        if not self.encryption_service:
            messagebox.showwarning("Data Access Error", "Encryption service is not ready. Cannot decrypt credentials.")
            _insert_info_message("INFO_NO_ENCRYPTION_SVC", "Encryption service not ready. Credentials may be unreadable.", "info_row_error"); return

        user_uid = self.current_user.get('uid')
        print(f"Refresh: Current User UID for fetching: {user_uid}")
        if not user_uid:
            messagebox.showerror("Error", "User UID missing. Cannot load credentials.")
            _insert_info_message("INFO_NO_USER_ID_REFRESH", "User UID missing. Credentials cannot be loaded.", "info_row_error"); return

        try:
            print(f"Refresh: Calling firebase_service.get_credentials_for_user with UID: {user_uid}, Search: '{search_term}'")
            credentials_data = self.firebase_service.get_credentials_for_user(user_uid, self.encryption_service, search_term) # CORRECTED METHOD NAME
            print(f"Refresh: Received {len(credentials_data) if credentials_data else 0} entries from Firebase service.")

            if not self.credential_tree.winfo_exists():
                print("Refresh: Treeview destroyed before populating."); return

            if credentials_data:
                for i, cred_doc in enumerate(credentials_data):
                    doc_id = cred_doc.get('id')
                    service_name = cred_doc.get('serviceName', 'N/A') # Expecting this field from service
                    login_id_val = cred_doc.get('loginId', 'N/A')     # Expecting this field from service
                    website_val = cred_doc.get('website', '')         # Expecting this field from service
                    tags_val = ", ".join(cred_doc.get('tags', []))    # Expecting this field from service
                    
                    # Password and notes are decrypted by the service or marked as DECRYPTION_ERROR
                    password_val = cred_doc.get('password', '') 
                    notes_val = cred_doc.get('notes', '')

                    print(f"Refresh: Processing entry {i+1}/{len(credentials_data)} - ID: {doc_id}, Service: {service_name}, Login: {login_id_val}")
                    
                    display_values = (doc_id, service_name, login_id_val, website_val, tags_val)
                    tags_to_apply_tree = ()

                    if password_val == "DECRYPTION_ERROR" or notes_val == "DECRYPTION_ERROR":
                        print(f"Refresh: Entry ID {doc_id} ({service_name}) marked as DECRYPTION_ERROR by service or UI.")
                        service_name_display = f"{service_name} (DECRYPTION FAILED)"
                        display_values = (doc_id, service_name_display, login_id_val, website_val, tags_val)
                        tags_to_apply_tree = ("info_row_decrypt_error",)
                    
                    if self.credential_tree.winfo_exists():
                        self.credential_tree.insert('', tk.END, iid=doc_id, values=display_values, tags=tags_to_apply_tree)
                print(f"Refresh: Finished populating tree with {len(credentials_data)} entries.")
            else:
                empty_message = "No credentials found." if not search_term else f"No credentials match '{search_term}'."
                _insert_info_message("INFO_EMPTY_LIST", empty_message)
                print(f"Refresh: {empty_message}")

        except InvalidToken:
            messagebox.showerror("Critical Decryption Error", "Failed to decrypt one or more credentials due to key mismatch. Please re-login. If issue persists, master password might be incorrect or data corrupted.")
            _insert_info_message("INFO_CRITICAL_DECRYPT_FAIL", "A critical decryption error occurred. Some data may be unreadable.", "info_row_error")
            print("Refresh: InvalidToken exception caught during list refresh (possibly at service level earlier).")
        except Exception as e:
            error_type = type(e).__name__
            print(f"Error refreshing credential list: {error_type}: {e}"); traceback.print_exc()
            messagebox.showerror("List Error", f"An unexpected error occurred while loading credentials: {e}")
            _insert_info_message("INFO_LIST_GENERIC_ERROR", f"Error loading credentials: {e}", "info_row_error")
        print("--- End of credential list refresh ---\n")

    # --- Profile Management ---
    def load_profile_data(self):
         if not self.current_user or not self.firebase_service.db:
             messagebox.showerror("Error", "Not logged in or database unavailable.")
             self.go_back()
             return
         
         self.edit_display_name_var.set(self.current_user.get('displayName', ''))
         self.edit_password_hint_var.set(self.current_user.get('passwordHint', '')) # Populated from current_user
         acc_rec_email = self.current_user.get('accountRecoveryEmail', self.current_user.get('email', ''))
         self.edit_account_recovery_email_var.set(acc_rec_email)
         
         self.edit_master_password_var.set("")
         self.edit_show_master_password_var.set(False)
         self.toggle_password_visibility(self.edit_master_password_entry, self.edit_show_master_password_var)

    def save_profile_changes(self):
        if not self.current_user or not self.firebase_service.db:
            messagebox.showerror("Error", "Not logged in or database unavailable."); return

        new_display_name = self.edit_display_name_var.get().strip()
        new_plain_master_password = self.edit_master_password_var.get()
        new_password_hint = self.edit_password_hint_var.get().strip()
        new_account_recovery_email = self.edit_account_recovery_email_var.get().strip()

        if not new_display_name:
            messagebox.showerror("Validation Error", "Display Name cannot be empty."); self.edit_display_name_entry.focus_set(); return
        
        if new_account_recovery_email and not self.validate_email_format(new_account_recovery_email):
            messagebox.showerror("Validation Error", "Invalid format for Account Recovery Email."); self.edit_account_recovery_email_entry.focus_set(); return

        if new_plain_master_password and len(new_plain_master_password) < 8:
            messagebox.showerror("Validation Error", "New Master Password must be at least 8 characters long."); self.edit_master_password_entry.focus_set(); return

        updates_for_profile_doc = {}
        # Use 'name' and 'recovery_email' for Firestore profile document as per service
        if new_display_name != self.current_user.get('displayName'):
            updates_for_profile_doc['name'] = new_display_name 
        if new_password_hint != self.current_user.get('passwordHint'):
            # If passwordHint is stored as 'pin_hash' (hashed), then update 'pin' to trigger hashing in service
            # If passwordHint is stored as a separate field, then 'passwordHint': new_password_hint
            # Assuming 'passwordHint' is the plain text hint that maps to profile's 'pin' for now for simplicity
            # Or firebase_service.update_user_profile needs to handle a 'passwordHint' field directly
            # For now, let's assume 'passwordHint' is for the 'pin' field in the profile doc (which gets hashed)
            # If the service doesn't have a 'pin' concept for general hint, this needs adjustment.
            # Let's assume for now there's a direct 'passwordHint' field in the profile doc managed by firebase_service.update_user_profile
            updates_for_profile_doc['passwordHint'] = new_password_hint # This requires service to handle 'passwordHint'
        if new_account_recovery_email != self.current_user.get('accountRecoveryEmail'):
            updates_for_profile_doc['recovery_email'] = new_account_recovery_email
        
        if not updates_for_profile_doc and not new_plain_master_password:
            messagebox.showinfo("No Changes", "No changes were detected in your profile information.")
            return

        op_kwargs = {
            "updates_for_profile_doc": updates_for_profile_doc,
            "new_plain_master_password": new_plain_master_password if new_plain_master_password else None,
        }
        self.show_loading_threaded(self.save_profile_button, self._perform_save_profile_operation, "Save Profile",
                                   op_kwargs=op_kwargs,
                                   callback_success=self._save_profile_success,
                                   callback_failure=self._save_profile_failure)

    def _perform_save_profile_operation(self, updates_for_profile_doc, new_plain_master_password):
        user_uid = self.current_user['uid']
        results = {"profile_doc_updated": False, "auth_password_updated": False, "re_encryption_status": None}

        if new_plain_master_password:
            auth_pass_success, auth_pass_error = self.firebase_service.update_user_auth_password(user_uid, new_plain_master_password)
            if not auth_pass_success:
                raise Exception(f"Failed to update master password in Firebase Auth: {auth_pass_error}")
            results["auth_password_updated"] = True
            print("Master password changed. Starting re-encryption of credentials...")
            
            old_encryption_service = self.encryption_service
            try:
                new_derived_key = derive_encryption_key(new_plain_master_password, self.current_user['encryptionSalt']) # Uses correct salt
                new_encryption_service_temp = EncryptionService(new_derived_key)

                all_db_credentials = self.firebase_service.get_credentials_for_user(user_uid, old_encryption_service, search_term=None) # CORRECTED METHOD NAME
                
                re_encrypted_count = 0
                re_encryption_errors = 0
                for entry in all_db_credentials:
                    if entry['id'] and entry.get('password') != "DECRYPTION_ERROR":
                        try:
                            plain_password_for_entry = entry['password']
                            plain_notes_for_entry = entry.get('notes', '')
                            
                            newly_encrypted_password = new_encryption_service_temp.encrypt(plain_password_for_entry)
                            newly_encrypted_notes = new_encryption_service_temp.encrypt(plain_notes_for_entry) if plain_notes_for_entry else ""
                            
                            # Pass to the service method that expects raw encrypted data
                            raw_updates = {
                                'encryptedPassword': newly_encrypted_password,
                                'encryptedNotes': newly_encrypted_notes
                            }
                            # Call the method that expects already encrypted data
                            update_ok = self.firebase_service.update_credential_entry_raw_encrypted(entry['id'], user_uid, raw_updates)
                            if update_ok: re_encrypted_count += 1
                            else: re_encryption_errors += 1
                        except Exception as re_enc_e:
                            print(f"Error re-encrypting entry {entry['id']}: {re_enc_e}"); traceback.print_exc()
                            re_encryption_errors +=1
                
                results["re_encryption_status"] = f"Re-encrypted: {re_encrypted_count} credentials. Errors: {re_encryption_errors}."
                if re_encryption_errors == 0:
                    self.encryption_service = new_encryption_service_temp
                    print("Re-encryption successful. App encryption service updated to use new master password.")
                else:
                    print("Re-encryption partially failed. App encryption service NOT fully updated. Advise re-login.")
                    results["re_encryption_status"] += " Some credentials might be unrecoverable if not manually updated. Please log out and log back in."
            except Exception as e_reencrypt:
                results["re_encryption_status"] = f"Critical error during re-encryption process: {e_reencrypt}"; traceback.print_exc()
        
        if updates_for_profile_doc:
            profile_success = self.firebase_service.update_user_profile(user_uid, updates_for_profile_doc)
            if not profile_success:
                raise Exception("Failed to update user profile details (name, hint, etc.) in Firestore.")
            results["profile_doc_updated"] = True
        
        return results

    def _save_profile_success(self, results):
        message_parts = ["Profile changes processed."]
        
        if results.get("profile_doc_updated"):
            updated_profile_from_db = self.firebase_service.get_user_profile_by_uid(self.current_user['uid'])
            if updated_profile_from_db:
                self.current_user['displayName'] = updated_profile_from_db.get('name', self.current_user['displayName']) # 'name' from service
                self.current_user['passwordHint'] = updated_profile_from_db.get('passwordHint', self.current_user.get('passwordHint')) # if service stores 'passwordHint'
                self.current_user['accountRecoveryEmail'] = updated_profile_from_db.get('recovery_email', self.current_user.get('accountRecoveryEmail')) # 'recovery_email'
            message_parts.append("Display name, hint, or recovery email updated.")

        if results.get("auth_password_updated"):
            message_parts.append("Master password updated in Firebase Authentication.")
            if results.get("re_encryption_status"):
                message_parts.append(results["re_encryption_status"])
            
            re_enc_status_str = results.get("re_encryption_status","")
            if "Errors: 0" not in re_enc_status_str or "Critical error" in re_enc_status_str:
                messagebox.showwarning("Profile Update Complications", "\n".join(message_parts) +
                                       "\n\nIMPORTANT: Your master password was changed, but there were issues re-encrypting some of your stored credentials. "
                                       "Please LOG OUT and LOG BACK IN with your NEW master password. Some credentials might appear as 'DECRYPTION FAILED'. "
                                       "You may need to manually re-enter those.")
            else:
                messagebox.showinfo("Profile Updated", "\n".join(message_parts) +
                                    "\n\nIf you changed your master password, the application has updated to use it for new and existing credentials.")
        else:
            messagebox.showinfo("Profile Updated", "\n".join(message_parts))

        self.update_welcome_message()
        self.show_form("dashboard")

    def _save_profile_failure(self, error):
        messagebox.showerror("Profile Update Failed", str(error))


    # --- Credential CRUD ---
    def save_new_credential(self):
        service_name = self.add_service_name_var.get().strip()
        login_id = self.add_login_id_var.get().strip()
        plain_password_val = self.add_password_var.get()
        website = self.add_website_var.get().strip()
        plain_notes = self.add_notes_text.get("1.0", tk.END).strip()
        tags_str = self.add_tags_var.get().strip()
        tags_list = [tag.strip() for tag in tags_str.split(',') if tag.strip()] if tags_str else []

        if not service_name: messagebox.showerror("Validation Error", "Service Name cannot be empty."); self.add_service_name_entry.focus_set(); return
        if not login_id: messagebox.showerror("Validation Error", "Login ID cannot be empty."); self.add_login_id_entry.focus_set(); return
        if not plain_password_val: messagebox.showerror("Validation Error", "Password cannot be empty."); self.add_password_entry.focus_set(); return

        if not self.current_user or not self.encryption_service or not self.firebase_service.db:
            messagebox.showerror("Error", "Not logged in, encryption service not ready, or database issue. Cannot save credential."); return
        
        current_uid_for_saving = self.current_user.get('uid')
        print(f"Attempting to save new credential for UID: {current_uid_for_saving}")
        if not current_uid_for_saving:
            messagebox.showerror("Critical Error", "User UID is missing. Please re-login before saving."); return

        op_args = (current_uid_for_saving, service_name, login_id, plain_password_val,
                   website, plain_notes, tags_list, self.encryption_service)
        self.show_loading_threaded(self.save_credential_button, self._perform_save_new_credential, "Save Credential",
                                   op_args=op_args,
                                   callback_success=lambda res_id: self._save_new_credential_success(res_id, service_name),
                                   callback_failure=self._save_new_credential_failure)

    def _perform_save_new_credential(self, user_uid, service_name, login_id, plain_password_val,
                                     website, plain_notes, tags_list, enc_service):
        # Call the corrected method name with all necessary parameters
        new_id = self.firebase_service.add_credential_entry(
            user_uid, service_name, login_id, plain_password_val,
            website, plain_notes, tags_list, enc_service
        )
        if not new_id:
            raise Exception("Failed to save credential entry to Firebase.")
        return new_id

    def _save_new_credential_success(self, new_id, service_name):
        print(f"Save new credential success for service '{service_name}', new ID: {new_id}. Refreshing list.")
        self.refresh_credential_list()
        messagebox.showinfo("Success", f"Credential entry for '{service_name}' added successfully.")
        self.show_form("dashboard")
        self.add_service_name_var.set("")
        self.add_login_id_var.set("")
        self.add_password_var.set("")
        self.add_website_var.set("")
        self.add_notes_text.delete("1.0", tk.END)
        self.add_tags_var.set("")
        self.add_show_password_var.set(False)
        self.toggle_password_visibility(self.add_password_entry, self.add_show_password_var)


    def _save_new_credential_failure(self, error):
        messagebox.showerror("Save Failed", f"Could not save new credential: {str(error)}")

    def edit_selected_credential(self):
        selected_items = self.credential_tree.selection()
        if not selected_items: messagebox.showwarning("Selection Error", "Please select an entry to view/edit."); return
        if len(selected_items) > 1: messagebox.showwarning("Selection Error", "Please select only one entry at a time."); return
        
        selected_iid = selected_items[0]
        if selected_iid.startswith("INFO_"): return

        if not self.current_user or not self.encryption_service or not self.firebase_service.db:
            messagebox.showerror("Error", "Not logged in, encryption service not ready, or database issue. Cannot load credential for editing."); return
        
        op_args = (selected_iid, self.current_user['uid'], self.encryption_service)
        self.show_loading_threaded(self.dashboard_edit_button, self._perform_load_credential_for_edit, f"{self.icons['edit']} View/Edit",
                                   op_args=op_args,
                                   callback_success=self._load_credential_for_edit_success,
                                   callback_failure=self._load_credential_for_edit_failure)

    def _perform_load_credential_for_edit(self, selected_iid, user_uid, enc_service):
        try:
            cred_data = self.firebase_service.get_credential_by_id(selected_iid, user_uid, enc_service) # CORRECTED METHOD NAME
        except InvalidToken:
            raise Exception("Decryption Error: Failed to load credential for editing due to key mismatch or corruption.")
        except Exception as e:
            raise Exception(f"Failed to load credential for editing: {e}")
        
        if not cred_data:
            raise Exception("Could not retrieve credential details. It may have been deleted or there's an access issue.")
        
        if cred_data.get('password') == "DECRYPTION_ERROR" or cred_data.get('notes') == "DECRYPTION_ERROR":
            print(f"Warning: Credential {selected_iid} has decryption errors. Password/Notes may be unrecoverable.")
        return cred_data

    def _load_credential_for_edit_success(self, cred_data):
        self.editing_credential_id = cred_data['id']
        
        self.edit_service_name_var.set(cred_data.get('serviceName',''))
        self.edit_login_id_var.set(cred_data.get('loginId',''))
        
        pwd_to_set = cred_data.get('password', '')
        notes_to_set = cred_data.get('notes', '')
        if pwd_to_set == "DECRYPTION_ERROR":
            messagebox.showwarning("Decryption Issue", "The password for this entry could not be decrypted. It might be corrupted or the encryption key changed. You can set a new password.")
        if notes_to_set == "DECRYPTION_ERROR":
             messagebox.showwarning("Decryption Issue", "The notes for this entry could not be decrypted. You can set new notes.")

        self.edit_password_var.set(pwd_to_set if pwd_to_set != "DECRYPTION_ERROR" else "")
        self.edit_notes_text.delete("1.0", tk.END)
        self.edit_notes_text.insert("1.0", notes_to_set if notes_to_set != "DECRYPTION_ERROR" else "")

        self.edit_website_var.set(cred_data.get('website',''))
        self.edit_tags_var.set(", ".join(cred_data.get('tags',[])))
        
        self.edit_show_password_var.set(False)
        self.toggle_password_visibility(self.edit_password_entry, self.edit_show_password_var)
        self.show_form("edit_credential")
        self.edit_service_name_entry.focus_set()


    def _load_credential_for_edit_failure(self, error):
        messagebox.showerror("Load for Edit Failed", str(error))
        self.refresh_credential_list()

    def save_edited_credential(self):
        if not self.editing_credential_id or not self.current_user or not self.encryption_service or not self.firebase_service.db:
            messagebox.showerror("Error", "No entry selected for editing, or critical services unavailable. Please go back to dashboard and try again.")
            self.show_form("dashboard")
            return

        service_name = self.edit_service_name_var.get().strip()
        login_id = self.edit_login_id_var.get().strip()
        plain_password_val = self.edit_password_var.get()
        website = self.edit_website_var.get().strip()
        plain_notes = self.edit_notes_text.get("1.0", tk.END).strip()
        tags_str = self.edit_tags_var.get().strip()
        tags_list = [tag.strip() for tag in tags_str.split(',') if tag.strip()] if tags_str else []

        if not service_name: messagebox.showerror("Validation Error", "Service Name cannot be empty."); self.edit_service_name_entry.focus_set(); return
        if not login_id: messagebox.showerror("Validation Error", "Login ID cannot be empty."); self.edit_login_id_entry.focus_set(); return
        if not plain_password_val: messagebox.showerror("Validation Error", "Password cannot be empty. If it was previously unrecoverable, please set a new one."); self.edit_password_entry.focus_set(); return
        
        updated_data_plain = {
            'serviceName': service_name,
            'loginId': login_id,
            'password': plain_password_val,
            'website': website,
            'notes': plain_notes,
            'tags': tags_list
        }
        
        op_args = (self.editing_credential_id, self.current_user['uid'], updated_data_plain, self.encryption_service)
        self.show_loading_threaded(self.save_edits_button, self._perform_save_edited_credential, "Save Changes",
                                   op_args=op_args,
                                   callback_success=lambda res: self._save_edited_credential_success(res, service_name),
                                   callback_failure=self._save_edited_credential_failure)

    def _perform_save_edited_credential(self, doc_id, user_uid, data_to_update_plain, enc_service):
        success = self.firebase_service.update_credential_entry(doc_id, user_uid, data_to_update_plain, enc_service) # CORRECTED METHOD NAME
        if not success:
            raise Exception("Failed to update credential entry in Firebase.")
        return success

    def _save_edited_credential_success(self, result, service_name):
        self.refresh_credential_list()
        messagebox.showinfo("Success", f"Credential entry for '{service_name}' updated successfully.")
        self.show_form("dashboard")
        self.editing_credential_id = None

    def _save_edited_credential_failure(self, error):
        messagebox.showerror("Update Failed", f"Could not update credential: {str(error)}")

    def delete_credential(self):
        selected_items_iids = self.credential_tree.selection()
        if not selected_items_iids:
            messagebox.showwarning("Selection Error", "Please select one or more entries to delete."); return
        
        actual_item_iids = [iid for iid in selected_items_iids if not iid.startswith("INFO_")]
        if not actual_item_iids:
            messagebox.showwarning("Selection Error", "No actual credential entries selected for deletion."); return

        if not self.current_user or not self.firebase_service.db:
            messagebox.showerror("Error", "Not logged in or database unavailable. Cannot delete."); return

        num_items = len(actual_item_iids)
        item_text = "entry" if num_items == 1 else "entries"
        confirm_msg = f"Are you sure you want to permanently delete the selected {num_items} credential {item_text}?"
        if not messagebox.askyesno("Confirm Deletion", confirm_msg):
            return

        op_args = (actual_item_iids, self.current_user['uid'])
        self.show_loading_threaded(self.dashboard_delete_button, self._perform_delete_credential, f"{self.icons['delete']} Delete",
                                   op_args=op_args,
                                   callback_success=self._delete_credential_success,
                                   callback_failure=self._delete_credential_failure)

    def _perform_delete_credential(self, iids_to_delete, user_uid):
        deleted_count = 0
        failed_ids = []
        for item_iid in iids_to_delete:
            success = self.firebase_service.delete_credential_entry(item_iid, user_uid) # CORRECTED METHOD NAME
            if success:
                deleted_count += 1
            else:
                failed_ids.append(item_iid)
        return {"deleted": deleted_count, "failed_ids": failed_ids, "total_attempted": len(iids_to_delete)}

    def _delete_credential_success(self, result):
        deleted_count = result["deleted"]
        failed_ids = result["failed_ids"]
        total_attempted = result["total_attempted"]
        
        if deleted_count > 0:
            msg = f"{deleted_count} of {total_attempted} credential entr{'y' if deleted_count == 1 else 'ies'} deleted successfully."
            if failed_ids:
                msg += f"\nCould not delete {len(failed_ids)} entr{'y' if len(failed_ids) == 1 else 'ies'} (ID(s): {', '.join(failed_ids[:3])}{'...' if len(failed_ids)>3 else ''})."
            messagebox.showinfo("Deletion Result", msg)
        elif failed_ids:
            messagebox.showerror("Deletion Failed", f"Could not delete the selected {total_attempted} entr{'y' if total_attempted == 1 else 'ies'}.")
        
        self.refresh_credential_list()

    def _delete_credential_failure(self, error):
        messagebox.showerror("Deletion Operation Failed", f"An error occurred during deletion: {str(error)}")
        self.refresh_credential_list()

    def copy_selected_password(self):
        selected_items = self.credential_tree.selection()
        if not selected_items: messagebox.showwarning("Copy Error", "Please select an entry to copy its password."); return
        selected_iid = selected_items[0]
        if selected_iid.startswith("INFO_"): return

        if not self.current_user or not self.encryption_service: return
        
        try:
            cred_data = self.firebase_service.get_credential_by_id(selected_iid, self.current_user['uid'], self.encryption_service) # CORRECTED METHOD NAME
            if cred_data and cred_data.get('password') and cred_data.get('password') != "DECRYPTION_ERROR":
                self.copy_to_clipboard(cred_data['password'], "Password")
            elif cred_data.get('password') == "DECRYPTION_ERROR":
                 messagebox.showerror("Copy Error", "Password for this entry is unrecoverable (decryption failed).")
            else:
                messagebox.showerror("Copy Error", "Could not retrieve password for copying.")
        except Exception as e:
            messagebox.showerror("Copy Error", f"Failed to get password: {e}")


    def copy_selected_login_id(self):
        selected_items = self.credential_tree.selection()
        if not selected_items: messagebox.showwarning("Copy Error", "Please select an entry to copy its Login ID."); return
        selected_iid = selected_items[0]
        if selected_iid.startswith("INFO_"): return

        item_values = self.credential_tree.item(selected_iid, 'values')
        if len(item_values) > 2 and item_values[2]:
            if "(DECRYPTION FAILED)" in item_values[1]:
                 messagebox.showwarning("Copy Info", "Login ID copied, but note that this entry has decryption issues.")
            self.copy_to_clipboard(item_values[2], "Login ID")
        else:
            messagebox.showerror("Copy Error", "Could not retrieve Login ID for copying.")


# --- Main Application Execution ---
if __name__ == "__main__":
    root = None 
    try:
        root = tk.Tk()
        root.minsize(900, 700)
        app = PasswordManagerApp(root)
        
        if app.firebase_service and app.firebase_service.db:
            root.mainloop()
        elif root and root.winfo_exists():
            print("Firebase initialization failed in PasswordManagerApp. Exiting.")
            root.destroy()

    except Exception as e:
        error_msg_trace = traceback.format_exc()
        full_error_msg = f"An unexpected fatal error occurred launching the application:\n{e}\n\n{error_msg_trace}"
        print(f"FATAL ERROR: {full_error_msg}")
        
        try:
            if root and root.winfo_exists():
                messagebox.showerror("Fatal Application Error", full_error_msg, parent=root)
                root.destroy()
            else:
                temp_root_for_error = tk.Tk()
                temp_root_for_error.withdraw()
                messagebox.showerror("Fatal Application Error", full_error_msg, parent=None)
                temp_root_for_error.destroy()
        except Exception as tk_error:
            print(f"Could not display fatal error in messagebox: {tk_error}")