import os
import json
import shutil
from datetime import datetime

def create_backup_directories():
    """Create necessary backup directories if they don't exist."""
    backup_types = ['database', 'chat_history', 'user_data']
    for backup_type in backup_types:
        backup_dir = os.path.join('backups', backup_type)
        os.makedirs(backup_dir, exist_ok=True)

def backup_chat_history(chat_messages):
    """Backup chat history to a JSON file."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_dir = os.path.join('backups', 'chat_history')
    backup_file = os.path.join(backup_dir, f'chat_backup_{timestamp}.json')
    
    chat_data = []
    for message in chat_messages:
        chat_data.append({
            'user_id': message.user_id,
            'message': message.message,
            'response': message.response,
            'timestamp': message.timestamp.isoformat()
        })
    
    with open(backup_file, 'w') as f:
        json.dump(chat_data, f, indent=4)
    
    return backup_file

def backup_user_data(users):
    """Backup user data to a JSON file."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_dir = os.path.join('backups', 'user_data')
    backup_file = os.path.join(backup_dir, f'user_backup_{timestamp}.json')
    
    user_data = []
    for user in users:
        user_data.append({
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'phone': user.phone,
            'email_verified': user.email_verified,
            'phone_verified': user.phone_verified
        })
    
    with open(backup_file, 'w') as f:
        json.dump(user_data, f, indent=4)
    
    return backup_file

def backup_database(db_path):
    """Create a copy of the SQLite database file."""
    if not os.path.exists(db_path):
        raise FileNotFoundError(f"Database file not found: {db_path}")
        
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_dir = os.path.join('backups', 'database')
    backup_file = os.path.join(backup_dir, f'database_backup_{timestamp}.db')
    
    shutil.copy2(db_path, backup_file)
    return backup_file

def restore_database(backup_path, db_path):
    """Restore database from a backup file."""
    if not os.path.exists(backup_path):
        raise FileNotFoundError(f"Backup file not found: {backup_path}")
        
    # Create a backup of the current database before restoring
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    current_backup = f"{db_path}.{timestamp}.bak"
    if os.path.exists(db_path):
        shutil.copy2(db_path, current_backup)
    
    # Restore the database
    shutil.copy2(backup_path, db_path)
    return True 