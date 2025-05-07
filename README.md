# Password Manager Pro (Firebase Secure Vault)

Password Manager Pro is a desktop application built with Python (Tkinter) that allows users to securely store and manage their login credentials. It uses Firebase for user authentication and Firestore as a cloud database, with client-side encryption to ensure that sensitive password data is protected even from the database administrators.

## Features

*   **User Authentication:** Secure user registration and login powered by Firebase Authentication.
*   **Master Password Recovery:** Password reset functionality via email (Firebase Auth).
*   **Cloud Storage:** Credentials stored securely in Google Firestore.
*   **Client-Side Encryption:**
    *   Master passwords are **not** stored directly.
    *   A unique salt is generated for each user.
    *   An encryption key is derived from the user's master password and their unique salt using PBKDF2HMAC-SHA256.
    *   All stored credential passwords and notes are encrypted using Fernet (AES-128-CBC) with the derived key **before** being sent to Firestore.
*   **Credential Management (CRUD):**
    *   Add new credential entries (Service Name, Login ID, Password, Website, Notes, Tags).
    *   View and search existing credentials.
    *   Edit existing credential entries.
    *   Delete credential entries.
*   **Strong Password Generator:** Built-in tool to generate strong, random passwords.
*   **Clipboard Management:**
    *   Copy passwords and login IDs to the clipboard.
    *   Automatic clipboard clearing after 30 seconds for enhanced security.
*   **User Profile Management:**
    *   Edit display name.
    *   Change master password (triggers re-encryption of all stored credentials).
    *   Update password hint and account recovery email.
*   **User-Friendly Interface:** Built with Tkinter and ttkthemes for a modern look and feel.
*   **Cross-Platform (Python Dependent):** Should run on any system where Python and Tkinter are available.

## Prerequisites

*   **Python 3.7+:** Ensure you have Python installed.
*   **pip:** Python package installer.
*   **Firebase Project:** You need an active Firebase project.
    *   Enable **Authentication** (Email/Password sign-in method).
    *   Enable **Firestore Database** (start in production or test mode).
*   **Firebase Admin SDK Service Account Key:**
    *   In your Firebase project settings, go to "Service accounts."
    *   Generate a new private key and download the JSON file.
*   **Firebase Web API Key:**
    *   In your Firebase project settings, under "General," find your Web API Key.

## Setup Instructions

1.  **Clone the Repository (or Download Files):**
    ```bash
    git clone <your-repository-url>
    cd <repository-directory>
    ```
    If you don't use Git, download `ui.py` and `firebase_service.py` into the same directory.

2.  **Install Dependencies:**
    Open your terminal or command prompt in the project directory and run:
    ```bash
    pip install tk Pillow firebase-admin bcrypt pyperclip cryptography requests
    ```
    *   `tk`: Usually comes with Python, but `Pillow` needs it for image support.
    *   `Pillow`: For graphical icons (optional, the app has text-based fallbacks).
    *   `firebase-admin`: For Firebase Admin SDK (server-side operations like user profile management in Firestore).
    *   `bcrypt`: For hashing the optional profile PIN (if used, currently part of profile hint).
    *   `pyperclip`: For clipboard copy/paste functionality.
    *   `cryptography`: For AES encryption (Fernet) and key derivation (PBKDF2HMAC).
    *   `requests`: For making HTTP requests to Firebase Authentication REST APIs.

3.  **Configure Firebase:**

    *   **Service Account Key:**
        *   Rename the downloaded JSON service account key file to `serviceAccountKey.json`.
        *   Place this `serviceAccountKey.json` file in the **same directory** as `ui.py` and `firebase_service.py`.
        *   **IMPORTANT:** Add `serviceAccountKey.json` to your `.gitignore` file if you are using Git to prevent committing sensitive credentials.
          ```
          # .gitignore
          serviceAccountKey.json
          __pycache__/
          *.pyc
          ```

    *   **Web API Key:**
        *   Open the `firebase_service.py` file.
        *   Find the line:
            ```python
            FIREBASE_WEB_API_KEY = "AIzaSyByybBiHCbwMWnFUlQGUW3qQ9e0Iws9ZLo" # <<< IMPORTANT: REPLACE THIS
            ```
        *   Replace `"AIzaSyByybBiHCbwMWnFUlQGUW3qQ9e0Iws9ZLo"` (or whatever placeholder is there) with your **actual Firebase Web API Key** obtained from your Firebase project settings.

4.  **Create Firestore Indexes (if prompted):**
    *   The first time you log in and the application tries to fetch credentials, Firestore might require a composite index for querying and ordering.
    *   The application's console output will display an error message with a direct link to create the required index in your Firebase console.
    *   Click the link, review the pre-filled index configuration (it should be for the `credentials` collection, on fields `user_id` and `serviceName`), and create the index.
    *   Wait for the index to finish building (status will change to "Enabled" in the Firebase console) before trying to log in again.

## Running the Application

Once all dependencies are installed and Firebase is configured:

1.  Navigate to the project directory in your terminal.
2.  Run the main UI file:
    ```bash
    python ui.py
    ```

## Usage

1.  **Register:**
    *   Click "Register New Account" on the login screen.
    *   Fill in your Full Name, Email (for login), a strong Master Password, and optionally a Password Hint and Account Recovery Email.
    *   **Your Master Password is critical and cannot be recovered directly by the application. Only a password reset via Firebase Authentication is possible, which allows you to set a new Master Password.**
2.  **Login:**
    *   Enter your registered Email and Master Password.
3.  **Dashboard:**
    *   **View Credentials:** Your stored credentials will be listed.
    *   **Search:** Use the search bar to filter credentials by service name, login ID, website, or tags.
    *   **Add New:** Click "Add New" to add a new credential entry.
    *   **View/Edit:** Select an entry and click "View/Edit" (or double-click) to modify its details.
    *   **Copy Pwd:** Select an entry and click "Copy Pwd" to copy the decrypted password to your clipboard (clears in 30s).
    *   **Delete:** Select one or more entries and click "Delete" to remove them.
    *   **Right-Click Context Menu:** Provides quick access to View/Edit, Copy Password, Copy Login ID, and Delete.
4.  **Add/Edit Credential Form:**
    *   **Service Name:** Name of the service (e.g., "Google", "Netflix").
    *   **Login ID:** Your username or email for that service.
    *   **Password:** The password for the service. You can use the "Generate" (⚙️) button to create a strong one. Click "Show" (👁️) to toggle visibility.
    *   **Website URL:** (Optional) The URL for the service.
    *   **Notes:** (Optional) Any additional notes for this entry.
    *   **Tags:** (Optional) Comma-separated tags for organization (e.g., "work, social").
5.  **Profile Page:**
    *   Access by clicking the "Profile" (👤) button on the dashboard.
    *   **Edit Display Name.**
    *   **Change Master Password:** If you enter a new master password, all your stored credentials will be re-encrypted with the new key derived from this new password. This process can take a moment if you have many credentials.
    *   **Edit Password Hint & Account Recovery Email.**
6.  **Logout:**
    *   Click the "Logout" (🚪) button on the dashboard. Your clipboard will be cleared.

## Security Considerations

*   **Master Password Strength:** The security of your entire vault depends on the strength of your master password. Choose a long, complex, and unique master password.
*   **Client-Side Encryption:** Your actual passwords for services are encrypted on your computer before being sent to Firebase. This means that even if Firebase servers were compromised, your passwords would remain encrypted (assuming the encryption key, derived from your master password, is not compromised).
*   **`serviceAccountKey.json`:** This file grants administrative access to your Firebase project. **Keep it secure and DO NOT commit it to public repositories.**
*   **Clipboard Clearing:** The automatic clipboard clearing is a security measure. Be mindful of what you copy.
*   **No Direct Master Password Recovery:** The application cannot directly tell you your master password. If forgotten, you must use the "Forgot Password?" link, which uses Firebase's email-based password reset. This will allow you to set a *new* master password. If you set a new master password this way, your old encrypted credentials will become **unreadable** unless you also update your master password within the "Edit Profile" section of the app *after* logging in with the new master password (which requires a re-encryption step). This re-encryption only happens if you change the master password *inside* the app's profile settings.

