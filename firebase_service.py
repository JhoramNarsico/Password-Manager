import firebase_admin
from firebase_admin import credentials, firestore, auth
from cryptography.fernet import InvalidToken # Import for specific exception handling if needed at service level
import bcrypt
import os
import base64
import requests
import time
import traceback 

# --- Firebase Configuration ---
FIREBASE_WEB_API_KEY = "AIzaSyDXSHN0qZ-OX6SoDhVJ2iciQs-ivgereEE" # <<< IMPORTANT: REPLACE THIS (Keep the user's key)
SIGN_IN_URL = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={FIREBASE_WEB_API_KEY}"
SIGN_UP_URL = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={FIREBASE_WEB_API_KEY}"
PASSWORD_RESET_URL = f"https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key={FIREBASE_WEB_API_KEY}"
CHANGE_PASSWORD_URL = f"https://identitytoolkit.googleapis.com/v1/accounts:update?key={FIREBASE_WEB_API_KEY}"

def hash_pin_value(plain_value: str) -> str:
    if not plain_value: return None
    salt = bcrypt.gensalt()
    hashed_bytes = bcrypt.hashpw(plain_value.encode('utf-8'), salt)
    return hashed_bytes.decode('utf-8')

def check_pin_hash(plain_value: str, hashed_value_str: str) -> bool:
    if not plain_value or not hashed_value_str: return False
    return bcrypt.checkpw(plain_value.encode('utf-8'), hashed_value_str.encode('utf-8'))

class FirebaseService:
    def __init__(self, credentials_path="serviceAccountKey.json"):
        self.db = None
        self.users_collection_ref = None
        self.credentials_collection_ref = None # RENAMED for clarity to match UI terms
        try:
            if not os.path.exists(credentials_path):
                error_message = (f"Error initializing Firebase: Credentials file not found at '{os.path.abspath(credentials_path)}'.\n"
                                 f"Please ensure 'serviceAccountKey.json' (or the specified path) is correct.")
                print(error_message); return
            cred = credentials.Certificate(credentials_path)
            if not firebase_admin._apps: firebase_admin.initialize_app(cred)
            self.db = firestore.client()
            self.users_collection_ref = self.db.collection('users')
            self.credentials_collection_ref = self.db.collection('credentials') # Use 'credentials' consistently
            print("Successfully connected to Firebase Firestore and Admin SDK initialized.")
        except Exception as e:
            error_message = (f"Error initializing Firebase in FirebaseService: {e}\n"
                             f"Using credentials path: '{os.path.abspath(credentials_path)}'.\n"
                             f"Please ensure the service account key is valid, accessible, "
                             "your system time is correct, and Firebase Admin SDK is correctly set up.")
            print(error_message); traceback.print_exc()

    def create_user_in_auth(self, email, password, display_name):
        if not self.db: return None, "Firebase not initialized"
        try:
            user_record = auth.create_user(email=email, password=password, display_name=display_name, email_verified=False)
            return user_record, None
        except auth.EmailAlreadyExistsError: return None, "exists"
        except Exception as e: print(f"Error creating user in Firebase Auth for '{email}': {e}"); traceback.print_exc(); return None, str(e)

    def sign_in_user_auth(self, email, password):
        if FIREBASE_WEB_API_KEY == "YOUR_WEB_API_KEY" or not FIREBASE_WEB_API_KEY.startswith("AIza"): # Added better check
             return None, "Firebase Web API Key not configured correctly."
        payload = {'email': email, 'password': password, 'returnSecureToken': True}
        try:
            response = requests.post(SIGN_IN_URL, json=payload); response.raise_for_status()
            return response.json(), None
        except requests.exceptions.HTTPError as e:
            error_json = e.response.json(); error_msg = error_json.get("error", {}).get("message", "Unknown authentication error")
            print(f"Firebase Auth sign-in error for '{email}': {error_msg} (Status: {e.response.status_code})")
            if "INVALID_PASSWORD" in error_msg or "EMAIL_NOT_FOUND" in error_msg or "INVALID_LOGIN_CREDENTIALS" in error_msg: 
                return None, "Invalid email or password."
            return None, f"Authentication failed: {error_msg}"
        except Exception as e: print(f"Error signing in user via REST API for '{email}': {e}"); traceback.print_exc(); return None, str(e)

    def send_password_reset_email_auth(self, email):
        if not self.db: return False, "Firebase not initialized"
        if FIREBASE_WEB_API_KEY == "YOUR_WEB_API_KEY" or not FIREBASE_WEB_API_KEY.startswith("AIza"):
             return False, "Firebase Web API Key not configured correctly."
        payload = {'requestType': 'PASSWORD_RESET', 'email': email}
        try:
            # Check if user exists in Auth first for better error message.
            # Note: This is an Admin SDK call, while reset is REST.
            # A user might exist in Auth but not have a profile doc yet.
            try: 
                auth.get_user_by_email(email)
            except auth.UserNotFoundError: 
                return False, "No account found with that email address." # More specific message
            except Exception as e_get_user: 
                print(f"Error checking user existence for {email} before reset: {e_get_user}")
                # Proceed with reset attempt anyway, Firebase REST API will handle it if user doesn't exist.

            response = requests.post(PASSWORD_RESET_URL, json=payload)
            response.raise_for_status() # Will raise for 4xx/5xx
            return True, "Password reset email sent if account exists."
        except requests.exceptions.HTTPError as e:
            error_msg = "Failed to send reset email"
            try:
                error_details = e.response.json().get("error", {}).get("message", "Unknown error")
                error_msg = f"Failed to send reset email: {error_details}"
            except: pass # Ignore if response is not JSON
            print(f"Firebase Auth password reset error for '{email}': {error_msg}"); return False, error_msg
        except Exception as e: print(f"Error sending password reset for '{email}': {e}"); traceback.print_exc(); return False, str(e)

    def update_user_auth_password(self, uid, new_password):
        if not self.db: return False, "Firebase not initialized"
        try: auth.update_user(uid, password=new_password); return True, None
        except Exception as e: print(f"Error updating Firebase Auth password for UID '{uid}': {e}"); traceback.print_exc(); return False, str(e)

    def create_user_profile(self, uid, name, email, recovery_email, plain_pin=None, password_hint_text=None): # Added password_hint_text
        if not self.users_collection_ref: return None, "Firestore 'users' collection not available."
        try:
            key_salt_bytes = os.urandom(16); key_salt_b64 = base64.urlsafe_b64encode(key_salt_bytes).decode('utf-8')
            hashed_pin = hash_pin_value(plain_pin) if plain_pin else None
            
            user_profile_data = {
                'name': name, 
                'email': email, 
                'key_salt': key_salt_b64, # This is the encryptionSalt
                'pin_hash': hashed_pin, 
                'recovery_email': recovery_email or email,
                'created_at': firestore.SERVER_TIMESTAMP, 
                'updated_at': firestore.SERVER_TIMESTAMP
            }
            if password_hint_text is not None: # Store plain text password hint if provided
                user_profile_data['passwordHint'] = password_hint_text

            self.users_collection_ref.document(uid).set(user_profile_data)
            return uid, None
        except Exception as e:
            print(f"Error creating Firestore user profile for UID '{uid}': {e}"); traceback.print_exc()
            try: auth.delete_user(uid)
            except Exception as del_e: print(f"Failed to rollback Auth user {uid} after profile error: {del_e}")
            return None, str(e)

    def get_user_profile_by_uid(self, uid):
        if not self.users_collection_ref: return None
        try:
            doc_ref = self.users_collection_ref.document(uid); doc = doc_ref.get()
            if doc.exists: user_data = doc.to_dict(); user_data['uid'] = doc.id; return user_data
            return None
        except Exception as e: print(f"Error getting user profile by UID '{uid}': {e}"); traceback.print_exc(); return None

    def update_user_profile(self, uid, data_to_update):
        if not self.users_collection_ref: return False
        try:
            # Handle specific fields that need transformation
            if 'pin' in data_to_update: # if UI sends 'pin' to change the hashed pin
                plain_pin = data_to_update.pop('pin')
                data_to_update['pin_hash'] = hash_pin_value(plain_pin) if plain_pin else None
            
            # Fields like 'name', 'recovery_email', 'passwordHint' can be updated directly
            # if they are in data_to_update and service expects them with these names.
            # e.g., if data_to_update contains 'name': 'New Name', it will update Firestore 'name' field.
            # UI sends {'name': ..., 'passwordHint': ..., 'recovery_email': ...}

            data_to_update['updated_at'] = firestore.SERVER_TIMESTAMP
            self.users_collection_ref.document(uid).update(data_to_update)
            return True
        except Exception as e: print(f"Error updating user profile for UID '{uid}': {e}"); traceback.print_exc(); return False

    # RENAMED and UPDATED
    def add_credential_entry(self, user_uid, service_name, login_id, plain_password_value, 
                             website, notes, tags, encryption_service):
        if not self.credentials_collection_ref or not encryption_service: 
            print("FirebaseService: add_credential_entry - Firestore collection or encryption service not available.")
            return None
        try:
            print(f"FirebaseService: add_credential_entry called for UID: {user_uid}, ServiceName: {service_name}")
            encrypted_password = encryption_service.encrypt(plain_password_value)
            encrypted_notes = encryption_service.encrypt(notes) if notes else ""

            entry_data = {
                'user_id': user_uid, 
                'serviceName': service_name,
                'loginId': login_id,
                'encryptedPassword': encrypted_password, # Storing encrypted password
                'website': website,
                'encryptedNotes': encrypted_notes, # Storing encrypted notes
                'tags': tags, 
                'created_at': firestore.SERVER_TIMESTAMP, 
                'updated_at': firestore.SERVER_TIMESTAMP
            }
            _timestamp, doc_ref = self.credentials_collection_ref.add(entry_data)
            print(f"FirebaseService: Credential entry added with ID: {doc_ref.id} for UID: {user_uid}")
            return doc_ref.id
        except Exception as e: 
            print(f"Error adding credential entry for service '{service_name}' (User: {user_uid}): {e}")
            traceback.print_exc()
            return None

    # RENAMED and UPDATED
    def get_credentials_for_user(self, user_uid, encryption_service, search_term=None):
        if not self.credentials_collection_ref or not encryption_service:
            print(f"FirebaseService: get_credentials_for_user returning early. Collection ref: {bool(self.credentials_collection_ref)}, Enc service: {bool(encryption_service)}")
            return []
        print(f"FirebaseService: get_credentials_for_user - Querying for user_id: '{user_uid}'")
        try:
            query = self.credentials_collection_ref.where('user_id', '==', user_uid)
            all_credentials_for_user = []
            retrieved_docs_count = 0

            # Order by serviceName. Firestore might require an index for this.
            for doc in query.order_by('serviceName').stream():
                retrieved_docs_count += 1
                entry = doc.to_dict()
                entry['id'] = doc.id
                print(f"FirebaseService: Fetched doc ID {doc.id}, ServiceName: {entry.get('serviceName', 'N/A')} for UID: {user_uid}")
                
                try:
                    encrypted_pwd_str = entry.get('encryptedPassword', '')
                    if encrypted_pwd_str:
                        entry['password'] = encryption_service.decrypt(encrypted_pwd_str) # Decrypt for UI
                    else: 
                        entry['password'] = ""
                    
                    encrypted_notes_str = entry.get('encryptedNotes', '')
                    if encrypted_notes_str:
                        entry['notes'] = encryption_service.decrypt(encrypted_notes_str) # Decrypt for UI
                    else:
                        entry['notes'] = ""

                except InvalidToken as decrypt_error_token:
                    print(f"FirebaseService: InvalidToken decrypting data for entry {entry['id']} (User: {user_uid}): {decrypt_error_token}")
                    if 'encryptedPassword' in entry: entry['password'] = "DECRYPTION_ERROR"
                    if 'encryptedNotes' in entry: entry['notes'] = "DECRYPTION_ERROR"
                except Exception as decrypt_error_generic:
                    print(f"FirebaseService: Generic error decrypting data for entry {entry['id']} (User: {user_uid}): {decrypt_error_generic}")
                    if 'encryptedPassword' in entry: entry['password'] = "DECRYPTION_ERROR"
                    if 'encryptedNotes' in entry: entry['notes'] = "DECRYPTION_ERROR"
                    traceback.print_exc()
                
                all_credentials_for_user.append(entry)
            
            print(f"FirebaseService: Retrieved {retrieved_docs_count} documents from Firestore for UID: {user_uid} before search term filter.")
            print(f"FirebaseService: Processed {len(all_credentials_for_user)} documents after decryption attempts.")
            
            if not search_term:
                print(f"FirebaseService: Returning {len(all_credentials_for_user)} entries (no search term).")
                return all_credentials_for_user
            
            st_lower = search_term.lower()
            print(f"FirebaseService: Filtering with search term: '{st_lower}'")
            
            filtered_results = [
                e for e in all_credentials_for_user 
                if st_lower in e.get('serviceName', '').lower() or \
                   st_lower in e.get('loginId', '').lower() or \
                   st_lower in e.get('website', '').lower() or \
                   any(st_lower in tag.lower() for tag in e.get('tags', []))
            ]
            print(f"FirebaseService: Returning {len(filtered_results)} entries after search term filter.")
            return filtered_results
        except Exception as e:
            print(f"Error fetching credentials for user UID '{user_uid}': {e}")
            traceback.print_exc()
            return []

    # RENAMED and UPDATED
    def get_credential_by_id(self, credential_id, user_uid_check, encryption_service):
        if not self.credentials_collection_ref or not encryption_service: return None
        try:
            doc_ref = self.credentials_collection_ref.document(credential_id)
            doc = doc_ref.get()
            if doc.exists:
                data = doc.to_dict()
                if data.get('user_id') == user_uid_check:
                    data['id'] = doc.id
                    try:
                        encrypted_pwd_str = data.get('encryptedPassword', '')
                        data['password'] = encryption_service.decrypt(encrypted_pwd_str) if encrypted_pwd_str else ""
                        
                        encrypted_notes_str = data.get('encryptedNotes', '')
                        data['notes'] = encryption_service.decrypt(encrypted_notes_str) if encrypted_notes_str else ""
                    except InvalidToken:
                        print(f"InvalidToken decrypting data for credential {data['id']} on get.")
                        if 'encryptedPassword' in data: data['password'] = "DECRYPTION_ERROR"
                        if 'encryptedNotes' in data: data['notes'] = "DECRYPTION_ERROR"
                    except Exception as decrypt_error:
                        print(f"Error decrypting data for credential {data['id']} on get: {decrypt_error}")
                        if 'encryptedPassword' in data: data['password'] = "DECRYPTION_ERROR"
                        if 'encryptedNotes' in data: data['notes'] = "DECRYPTION_ERROR"
                    return data
            return None
        except Exception as e:
            print(f"Error getting credential entry '{credential_id}': {e}")
            traceback.print_exc()
            return None

    # RENAMED and UPDATED
    def update_credential_entry(self, credential_id, user_uid_check, data_to_update_plain, encryption_service):
        if not self.credentials_collection_ref or not encryption_service: return False
        try:
            doc_ref = self.credentials_collection_ref.document(credential_id)
            doc_snapshot = doc_ref.get()
            if not doc_snapshot.exists or doc_snapshot.to_dict().get('user_id') != user_uid_check:
                print(f"Update failed: Credential entry {credential_id} not found or user mismatch.")
                return False

            update_data_encrypted = {}
            
            # Fields that are stored as plain text
            for field in ['serviceName', 'loginId', 'website', 'tags']:
                if field in data_to_update_plain:
                    update_data_encrypted[field] = data_to_update_plain[field]

            # Encrypt password if provided and not an error marker
            if 'password' in data_to_update_plain and \
               data_to_update_plain['password'] is not None and \
               data_to_update_plain['password'] != "DECRYPTION_ERROR":
                update_data_encrypted['encryptedPassword'] = encryption_service.encrypt(data_to_update_plain['password'])
            
            # Encrypt notes if provided (can be empty string)
            if 'notes' in data_to_update_plain:
                 update_data_encrypted['encryptedNotes'] = encryption_service.encrypt(data_to_update_plain['notes']) if data_to_update_plain['notes'] else ""
            
            if not update_data_encrypted: # No actual data to update
                print(f"No data to update for credential entry {credential_id}")
                return True 

            update_data_encrypted['updated_at'] = firestore.SERVER_TIMESTAMP
            doc_ref.update(update_data_encrypted)
            return True
        except Exception as e:
            print(f"Error updating credential entry '{credential_id}': {e}")
            traceback.print_exc()
            return False
            
    # RENAMED (but name was already correct) and UPDATED for new fields
    def update_credential_entry_raw_encrypted(self, credential_id, user_uid_check, raw_updates):
        # raw_updates should contain 'encryptedPassword' and/or 'encryptedNotes'
        if not self.credentials_collection_ref: return False
        try:
            doc_ref = self.credentials_collection_ref.document(credential_id)
            doc_snapshot = doc_ref.get()
            if not doc_snapshot.exists or doc_snapshot.to_dict().get('user_id') != user_uid_check:
                return False
            
            update_payload = {}
            if 'encryptedPassword' in raw_updates:
                update_payload['encryptedPassword'] = raw_updates['encryptedPassword']
            if 'encryptedNotes' in raw_updates:
                 update_payload['encryptedNotes'] = raw_updates['encryptedNotes']

            if not update_payload: # Nothing to update
                return True

            update_payload['updated_at'] = firestore.SERVER_TIMESTAMP
            doc_ref.update(update_payload)
            return True
        except Exception as e:
            print(f"Error raw updating credential entry '{credential_id}': {e}")
            traceback.print_exc()
            return False

    # RENAMED
    def delete_credential_entry(self, credential_id, user_uid_check):
        if not self.credentials_collection_ref: return False
        try:
            doc_ref = self.credentials_collection_ref.document(credential_id)
            doc_snapshot = doc_ref.get()
            if not doc_snapshot.exists or doc_snapshot.to_dict().get('user_id') != user_uid_check:
                print(f"Delete failed: Credential entry {credential_id} not found or user mismatch.")
                return False
            doc_ref.delete()
            return True
        except Exception as e:
            print(f"Error deleting credential entry '{credential_id}': {e}")
            traceback.print_exc()
            return False