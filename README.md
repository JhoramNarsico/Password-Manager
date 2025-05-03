# Tkinter Password Manager

A desktop-based password manager application built with Python's Tkinter GUI toolkit and MySQL for data storage. This application provides basic functionality for user registration, login, and managing password entries.

**⚠️ IMPORTANT SECURITY WARNING ⚠️**

This application, in its current state as provided in the initial code, stores **user account passwords and saved website/application passwords in PLAIN TEXT** in the database. This is **EXTREMELY INSECURE** and makes the stored credentials highly vulnerable.

**DO NOT USE THIS APPLICATION FOR REAL SENSITIVE PASSWORDS WITHOUT IMPLEMENTING PROPER SECURITY MEASURES:**

1.  **User Password Hashing:** User account passwords (`users` table) MUST be hashed using a strong algorithm like bcrypt or Argon2 before storing them.
2.  **Stored Password Encryption:** Passwords saved for websites/apps (`passwords` table) MUST be encrypted using a strong symmetric encryption algorithm (like AES-GCM). The encryption key should ideally be derived from the user's master password or managed securely.

This project primarily serves as an educational example demonstrating Tkinter GUI development, database interaction with MySQL, and application structure. **It is NOT a production-ready secure password manager.**

## Features

*   User Registration with email and password.
*   User Login.
*   Password Recovery simulation (checks if recovery email exists).
*   Add new password entries (Website/App Name, Username, Password, Associated Email).
*   View stored passwords in a list (excluding the actual password for security).
*   Edit existing password entries.
*   Delete password entries.
*   Search functionality for password entries (by App Name, Username, or Email).
*   Edit User Profile (Name, New Password, Recovery Email, PIN - PIN security also needs improvement).
*   Password strength indicator during registration.
*   Show/Hide password visibility toggle.
*   Basic input validation (e.g., email format).
*   Themed UI using `ttk` styles.

## Screenshots (Placeholder)

*(It's highly recommended to add screenshots of your application here)*

*   *Login Screen*
*   *Registration Screen*
*   *Dashboard View*
*   *Add/Edit Password Form*

## Prerequisites

*   **Python 3.x:** Download from [python.org](https://www.python.org/)
*   **pip:** Usually included with Python installations.
*   **MySQL Server:** A running MySQL database server (e.g., local installation, Docker container, cloud service). Download from [mysql.com](https://www.mysql.com/downloads/) or use package managers like `apt` or `brew`.

## Installation and Setup

1.  **Clone the Repository:**
    ```bash
    git clone <your-repository-url>
    cd <repository-directory>
    ```

2.  **Create a Virtual Environment (Recommended):**
    ```bash
    python -m venv venv
    ```
    *   Activate the environment:
        *   Windows (cmd/powershell): `.\venv\Scripts\activate`
        *   macOS/Linux (bash/zsh): `source venv/bin/activate`

3.  **Install Dependencies:**
    Create a `requirements.txt` file with the following content:
    ```txt
    mysql-connector-python
    # Add other libraries if you implement hashing/encryption, e.g.:
    # bcrypt
    # cryptography
    ```
    Then install:
    ```bash
    pip install -r requirements.txt
    ```

4.  **Database Setup:**
    *   Ensure your MySQL server is running.
    *   Connect to your MySQL server using a client (e.g., `mysql` command line, MySQL Workbench, DBeaver).
    *   Create the database and tables using the provided SQL schema. You can execute the content of the `database_schema.sql` file (or the schema provided in previous responses):
        ```sql
        -- Example using mysql command line:
        mysql -u your_mysql_user -p < database_schema.sql
        ```
        *(Replace `your_mysql_user` with your MySQL username)*
        *Make sure the `database_schema.sql` file contains the `CREATE DATABASE`, `USE database`, and `CREATE TABLE` statements.*

5.  **Configuration:**
    *   Open the Python script (e.g., `password_manager_app.py`).
    *   Locate the `self.db_config` dictionary within the `__init__` method:
        ```python
        self.db_config = {
            'host': 'localhost',         # Change if DB is not local
            'user': 'your_db_user',      # CHANGE THIS to your DB username
            'password': 'your_db_password', # CHANGE THIS to your DB password
            'database': 'password_manager' # Change if you used a different DB name
        }
        ```
    *   **IMPORTANT:** Update the `user` and `password` values to match your MySQL database credentials. For production, avoid hardcoding credentials; use environment variables or a secure configuration file instead.

## Running the Application

1.  Make sure your virtual environment is activated.
2.  Make sure your MySQL server is running.
3.  Navigate to the project directory in your terminal.
4.  Run the main Python script:
    ```bash
    python password_manager_app.py
    ```
    *(Replace `password_manager_app.py` with the actual filename if you saved it differently).*

## Security Considerations (Summary)

*   **Plain Text Passwords:** The biggest flaw. Implement hashing and encryption immediately if used for real data.
*   **Database Credentials:** Avoid hardcoding in the script for production deployments.
*   **PIN Security:** Treat PINs like passwords; hash them or use more secure verification methods.
*   **Input Sanitization:** While basic validation exists, ensure robust sanitization against potential injection attacks if extending functionality.
*   **Error Handling:** Sensitive information should not be leaked in error messages shown to the user.
*   **Session Management:** This desktop app uses a simple `current_user` variable. Web apps would need secure session handling.

## Future Improvements / TODO

*   **Implement Hashing & Encryption (Critical):** Use bcrypt/Argon2 for user passwords and AES for stored passwords.
*   **Password Generation:** Add a feature to generate strong, random passwords.
*   **Clipboard Integration:** Copy passwords to the clipboard securely (with auto-clear after a timeout).
*   **Secure Configuration:** Load DB credentials from environment variables or a config file.
*   **Enhanced UI/UX:** Use icons, improve layout, potentially add custom themes.
*   **Actual Email Sending:** Implement password recovery email sending using `smtplib` or an email service API.
*   **Two-Factor Authentication (2FA):** Add an extra layer of security for login.
*   **Password History:** Keep track of previous passwords for an entry.
*   **Audit Log:** Log important actions (login attempts, password changes).
*   **Import/Export:** Allow users to import/export their password data securely (e.g., encrypted CSV/JSON).
*   **More Robust Error Handling:** Provide more specific and user-friendly error feedback.

## License

(Optional: Choose a license if you plan to share the code)

Example:
`This project is licensed under the MIT License - see the LICENSE.md file for details.`

*(If you choose MIT, create a `LICENSE.md` file with the standard MIT License text).*

## Contributing

(Optional: Add guidelines if you want others to contribute)

Example:
`Contributions are welcome! Please feel free to submit a pull request or open an issue.`
