import os
import random
from flask import Flask, request, render_template, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import logging
from datetime import datetime, timedelta
from functools import wraps
import requests
from twilio.rest import Client
import json
import re
from dotenv import load_dotenv
from utils.backup_utils import (
    create_backup_directories,
    backup_chat_history,
    backup_user_data,
    backup_database,
    restore_database
)
import speech_recognition as sr
import hashlib
import base64
from werkzeug.utils import secure_filename

# Load environment variables from .env file
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Database initialization
db = SQLAlchemy(app)

# Login manager initialization
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Mail configuration (optional)
if os.getenv('MAIL_USERNAME') and os.getenv('MAIL_PASSWORD'):
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
    mail = Mail(app)
else:
    mail = None
    print("Warning: Mail service not configured. Email functionality will be disabled.")

# Twilio configuration (optional)
if os.getenv('TWILIO_ACCOUNT_SID') and os.getenv('TWILIO_AUTH_TOKEN') and os.getenv('TWILIO_PHONE_NUMBER'):
    TWILIO_SID = os.getenv('TWILIO_ACCOUNT_SID')
    TWILIO_AUTH_TOKEN = os.getenv('TWILIO_AUTH_TOKEN')
    TWILIO_PHONE_NUMBER = os.getenv('TWILIO_PHONE_NUMBER')
    twilio_client = Client(TWILIO_SID, TWILIO_AUTH_TOKEN)
else:
    twilio_client = None
    print("Warning: Twilio service not configured. SMS functionality will be disabled.")

# Logging configuration
logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Constants and Configuration
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx'}
UPLOAD_FOLDER = os.path.join('static', 'uploads')
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size

# Helper Functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_file(file, subfolder):
    if file and allowed_file(file.filename):
        filename = secure_filename(f"{int(datetime.utcnow().timestamp())}_{file.filename}")
        upload_dir = os.path.join(app.root_path, UPLOAD_FOLDER, subfolder)
        os.makedirs(upload_dir, exist_ok=True)
        filepath = os.path.join(upload_dir, filename)
        file.save(filepath)
        return os.path.join(subfolder, filename)
    return None

def handle_file_upload(file, subfolder, model_class, **kwargs):
    try:
        if not file:
            raise ValueError('No file selected')
            
        file_path = save_file(file, subfolder)
        if not file_path:
            raise ValueError('Invalid file type')
            
        file_size = os.path.getsize(os.path.join(app.root_path, UPLOAD_FOLDER, file_path))
        
        new_file = model_class(
            file_path=file_path,
            file_size=file_size,
            **kwargs
        )
        db.session.add(new_file)
        db.session.commit()
        
        return True, 'File uploaded successfully!'
    except Exception as e:
        logger.error(f'Error uploading file: {str(e)}')
        return False, f'Error uploading file: {str(e)}'

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    phone = db.Column(db.String(20), unique=True, nullable=True)  # Made optional
    email_verified = db.Column(db.Boolean, default=True)  # Set default to True
    phone_verified = db.Column(db.Boolean, default=True)  # Set default to True
    verification_code = db.Column(db.String(6), nullable=True)
    # Add relationship to chat messages
    messages = db.relationship('ChatMessage', backref='user', lazy=True)
    profile = db.relationship('UserProfile', backref='user', uselist=False)

    def check_password(self, password):
        return check_password_hash(self.password, password)

# Chat message model
class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    response = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Update the VoiceAuth model
class VoiceAuth(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    voice_template = db.Column(db.LargeBinary, nullable=True)  # Store voice template
    voice_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used = db.Column(db.DateTime, default=datetime.utcnow)
    is_enrolled = db.Column(db.Boolean, default=False)  # Track if voice is enrolled

# Add UserProfile model
class UserProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    full_name = db.Column(db.String(100))
    bio = db.Column(db.Text)
    avatar_path = db.Column(db.String(255))
    location = db.Column(db.String(100))
    website = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# Add file upload model
class UserFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(255), nullable=False)
    file_type = db.Column(db.String(50))
    file_size = db.Column(db.Integer)  # Size in bytes
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref=db.backref('files', lazy=True))

# Add Indian Justice System Models
class CourtCase(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cnr_number = db.Column(db.String(16), unique=True)  # Case Number Record
    filing_number = db.Column(db.String(50))
    filing_date = db.Column(db.DateTime, default=datetime.utcnow)
    case_type = db.Column(db.String(50))  # Civil, Criminal, etc.
    case_status = db.Column(db.String(50))  # Pending, Disposed, etc.
    court_name = db.Column(db.String(100))
    court_type = db.Column(db.String(50))  # Supreme Court, High Court, District Court
    petitioner_name = db.Column(db.String(100))
    respondent_name = db.Column(db.String(100))
    advocate_name = db.Column(db.String(100))
    last_hearing_date = db.Column(db.DateTime)
    next_hearing_date = db.Column(db.DateTime)
    purpose_of_hearing = db.Column(db.String(200))
    act = db.Column(db.String(100))  # IPC, CrPC, etc.
    section = db.Column(db.String(100))  # Section numbers
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class CaseHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('court_case.id'), nullable=False)
    hearing_date = db.Column(db.DateTime)
    court_proceedings = db.Column(db.Text)
    order_passed = db.Column(db.Text)
    next_date = db.Column(db.DateTime)
    purpose = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class CourtOrder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('court_case.id'), nullable=False)
    order_date = db.Column(db.DateTime)
    order_type = db.Column(db.String(50))  # Interim, Final, etc.
    order_details = db.Column(db.Text)
    judge_name = db.Column(db.String(100))
    order_file_path = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Advocate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    registration_number = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(100))
    bar_council = db.Column(db.String(100))
    enrollment_date = db.Column(db.DateTime)
    practice_areas = db.Column(db.String(500))
    phone = db.Column(db.String(20))
    email = db.Column(db.String(120))
    address = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Court(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    court_name = db.Column(db.String(100))
    court_type = db.Column(db.String(50))  # Supreme Court, High Court, District Court
    state = db.Column(db.String(50))
    district = db.Column(db.String(50))
    address = db.Column(db.Text)
    establishment_date = db.Column(db.DateTime)
    jurisdiction = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Judge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    court_id = db.Column(db.Integer, db.ForeignKey('court.id'))
    designation = db.Column(db.String(100))
    appointment_date = db.Column(db.DateTime)
    retirement_date = db.Column(db.DateTime)
    specialization = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class CauseLists(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    court_id = db.Column(db.Integer, db.ForeignKey('court.id'))
    hearing_date = db.Column(db.DateTime)
    case_type = db.Column(db.String(50))
    total_cases = db.Column(db.Integer)
    pdf_link = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class LegalAct(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    act_name = db.Column(db.String(200))
    act_number = db.Column(db.String(50))
    year = db.Column(db.Integer)
    description = db.Column(db.Text)
    pdf_link = db.Column(db.String(255))
    is_amended = db.Column(db.Boolean, default=False)
    last_amended_date = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class LegalDocument(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    document_type = db.Column(db.String(50))  # FIR, Charge Sheet, Vakalatnama, etc.
    case_id = db.Column(db.Integer, db.ForeignKey('court_case.id'))
    document_number = db.Column(db.String(50))
    filing_date = db.Column(db.DateTime)
    filed_by = db.Column(db.String(100))
    document_path = db.Column(db.String(255))
    is_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class FIR(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fir_number = db.Column(db.String(50), unique=True)
    police_station = db.Column(db.String(100))
    district = db.Column(db.String(50))
    state = db.Column(db.String(50))
    filing_date = db.Column(db.DateTime)
    incident_date = db.Column(db.DateTime)
    complainant_name = db.Column(db.String(100))
    accused_name = db.Column(db.String(100))
    sections = db.Column(db.String(200))
    investigation_officer = db.Column(db.String(100))
    status = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Add this function before the routes
def get_bot_response(message):
    # Convert message to lowercase for easier matching
    message = message.lower()
    
    # Check for news-related queries
    if re.search(r'news|latest|updates|recent', message):
        try:
            # Using NewsAPI to get latest Indian legal news
            news_api_key = "YOUR_NEWS_API_KEY"  # Replace with your API key
            url = f"https://newsapi.org/v2/everything?q=india+supreme+court+law&apiKey={news_api_key}&pageSize=3"
            response = requests.get(url)
            if response.status_code == 200:
                news = response.json()
                if news['articles']:
                    news_response = "Here are the latest Indian legal news:\n\n"
                    for article in news['articles']:
                        news_response += f"- {article['title']}\n"
                    return news_response
        except Exception as e:
            logger.error(f"Error fetching news: {str(e)}")

    # India-specific legal patterns
    india_patterns = {
        r'ministry of law|law ministry|lawmin': '''Ministry of Law & Justice, Government of India:
Key Departments:
1. Department of Legal Affairs
2. Legislative Department
3. Department of Justice

Current Minister: Shri Arjun Ram Meghwal
Website: https://www.justice.gov/
Contact: Ministry of Law & Justice, Shastri Bhawan, New Delhi''',

        r'legal affairs department|legal department': '''Department of Legal Affairs Functions:
1. Legal advice to Ministries/Departments
2. Attorney General's office
3. Treaties and agreements
4. Legal profession regulation
5. Notaries appointment
6. Legal aid to poor

Visit: https://legalaffairs.gov.in/''',

        r'legislative department|law making': '''Legislative Department:
1. Drafting of Central legislation
2. Election laws
3. Constitutional matters
4. Official languages
5. State legislations
6. Law Commission reports

Resources: https://legislative.gov.in/''',

        r'department of justice|justice department': '''Department of Justice:
1. Appointment of Supreme Court/High Court judges
2. Court infrastructure
3. Legal reforms
4. Access to justice
5. Judicial administration
6. E-Courts project

Visit: https://doj.gov.in/''',

        r'indian constitution|constitution of india': '''Constitution of India:
- Adopted: 26 November 1949
- Enforced: 26 January 1950
- Parts: 25
- Articles: 395
- Schedules: 12
- Fundamental Rights: Articles 12-35
- Directive Principles: Articles 36-51
- Fundamental Duties: Article 51A

Access at: https://legislative.gov.in/constitution-of-india''',

        r'supreme court india|sc india': '''Supreme Court of India:
- Chief Justice: Hon'ble Dr. Justice D.Y. Chandrachud
- Location: Tilak Marg, New Delhi
- Jurisdiction: Entire territory of India
- Constitutional Powers: Articles 124-147
- E-filing: https://efiling.sci.gov.in/
- Cause Lists: https://main.sci.gov.in/causelist
- Judgments: https://main.sci.gov.in/judgments''',

        r'high court india|hc india': '''High Courts in India:
- Total High Courts: 25
- Article 214: High Court for each state
- Original and Appellate Jurisdiction
- Powers under Article 226
- Subordinate Courts supervision
- E-filing facilities available
- Cause lists published daily

Find your High Court: https://ecourts.gov.in/ecourts_home/static/highcourts.php''',

        r'district court|lower court': '''District Courts in India:
- Established under State jurisdiction
- Civil and Criminal jurisdiction
- Principal District Judge heads
- Types: District, Sessions, Family Courts
- Small Causes Courts
- Metropolitan Magistrate Courts
- E-Courts services available

Access: https://districts.ecourts.gov.in/''',

        r'legal aid|free legal help': '''Legal Aid in India:
1. NALSA (National Legal Services Authority)
- Toll-free: 1516
- Website: nalsa.gov.in

2. Eligibility:
- Women and children
- SC/ST members
- Industrial workmen
- Victims of disasters
- Persons with disabilities
- Persons in custody
- Low income groups

3. Services:
- Free legal representation
- Legal advice
- Lok Adalats
- Legal awareness camps''',

        r'file case|court filing': '''Filing Cases in India:
1. Civil Cases:
- File through District Courts
- Pay court fees online
- Submit documents digitally

2. Criminal Cases:
- File FIR at Police Station
- Track on CCTNS
- Court proceedings via e-Courts

3. E-Filing Portal:
- https://efiling.ecourts.gov.in/
- Digital signatures required
- Online fee payment
- Document upload facility''',

        r'fir|police complaint': '''Filing FIR in India:
1. Visit nearest Police Station
2. Online FIR filing: https://digitalpolice.gov.in/
3. Zero FIR facility available
4. Track FIR status online
5. Get free copy of FIR
6. Time-bound investigation

Emergency: Dial 112''',

        r'cyber crime|online crime': '''Cyber Crime Reporting:
1. National Cyber Crime Portal:
- cybercrime.gov.in
- Toll-free: 1930
- Report online financial fraud
- Report social media crimes

2. Types of Complaints:
- Online fraud
- Cyberstalking
- Data theft
- Online harassment
- Social media crimes''',

        r'consumer complaint|consumer rights': '''Consumer Rights in India:
1. E-Daakhil Portal:
- edaakhil.nic.in
- File consumer complaints
- Track complaint status
- Online mediation

2. Consumer Helpline:
- Toll-free: 1915
- WhatsApp: 8800001915
- Email: nch.doca@nic.in''',

        r'property law|land law': '''Property Laws in India:
1. Key Acts:
- Transfer of Property Act
- Registration Act
- RERA Act
- Land Acquisition Act

2. Property Registration:
- Sub-registrar offices
- E-registration available
- Property cards
- Land records digitization

Visit: https://legislative.gov.in/property-laws''',

        r'family law|marriage law': '''Family Laws in India:
1. Hindu Laws:
- Hindu Marriage Act
- Hindu Succession Act
- Hindu Adoption Act

2. Muslim Laws:
- Muslim Personal Law
- Wakf Act

3. Other Laws:
- Special Marriage Act
- Indian Succession Act
- Guardianship Act''',

        r'labour law|employment law': '''Labour Laws in India:
1. Key Acts:
- Industrial Relations Code
- Code on Wages
- Social Security Code
- Occupational Safety Code

2. Rights:
- Minimum wages
- Social security
- Safe working conditions
- Trade union formation

Portal: https://labour.gov.in/''',

        r'help|assistance': '''I can help you with:
1. Indian Legal System
2. Constitutional Rights
3. Filing Cases/Complaints
4. Court Information
5. Legal Aid
6. Consumer Rights
7. Property Laws
8. Family Laws
9. Labour Laws
10. Cyber Laws

What specific information do you need?''',

        r'thank you|thanks': 'You\'re welcome! For more information, visit the Ministry of Law & Justice website: https://lawmin.gov.in/',

        r'bye|goodbye': 'Thank you for using the Indian Legal Assistant. Visit https://lawmin.gov.in/ for more information. Have a great day!'
    }

    # Check for time-related questions
    if re.search(r'time|current time', message):
        return f"The current time is {datetime.now().strftime('%I:%M %p')} IST"
    
    # Check for date-related questions
    if re.search(r'date|today', message):
        return f"Today's date is {datetime.now().strftime('%B %d, %Y')}"
    
    # Check India-specific patterns first
    for pattern, response in india_patterns.items():
        if re.search(pattern, message):
            return response
    
    # Default response
    return '''I can help you with information about the Indian legal system, including:
1. Ministry of Law & Justice
2. Indian Constitution
3. Courts System
4. Legal Rights
5. Filing Cases/Complaints
6. Legal Aid
7. Various Laws (Property, Family, Labour, etc.)

Please specify what information you need about these topics.

For official information, visit: https://lawmin.gov.in/'''

def process_voice_audio(audio_file, user_id):
    """Helper function to process voice audio files"""
    temp_filename = f"temp_audio_{user_id}_{int(datetime.utcnow().timestamp())}.wav"
    temp_filepath = os.path.join(app.root_path, 'temp', temp_filename)
    
    # Ensure temp directory exists
    os.makedirs(os.path.join(app.root_path, 'temp'), exist_ok=True)
    
    try:
        # Save the file temporarily
        audio_file.save(temp_filepath)
        
        # Initialize recognizer
        recognizer = sr.Recognizer()
        
        # Process the audio file
        with sr.AudioFile(temp_filepath) as source:
            # Adjust for ambient noise
            recognizer.adjust_for_ambient_noise(source)
            # Record the audio
            audio = recognizer.record(source)
            
            # Convert speech to text
            text = recognizer.recognize_google(audio).lower()
            
            # Get voice characteristics
            voice_data = audio.get_raw_data()
            voice_hash = hashlib.sha256(voice_data).hexdigest()
            
            return {
                'success': True,
                'text': text,
                'voice_data': voice_data,
                'voice_hash': voice_hash
            }
    except sr.UnknownValueError:
        return {
            'success': False,
            'error': 'Could not understand audio'
        }
    except sr.RequestError as e:
        return {
            'success': False,
            'error': f'Error processing audio: {str(e)}'
        }
    except Exception as e:
        return {
            'success': False,
            'error': f'Error: {str(e)}'
        }
    finally:
        # Clean up - remove temporary file
        if os.path.exists(temp_filepath):
            os.remove(temp_filepath)

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        phone = request.form.get('phone')  # Now optional

        # Input validation
        if not username or not password or not email:
            flash('Username, password and email are required')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('register'))

        # Create new user
        hashed_password = generate_password_hash(password)
        user = User(
            username=username,
            password=hashed_password,
            email=email,
            phone=phone if phone else None  # Handle optional phone
        )
        db.session.add(user)
        db.session.commit()

        logger.info(f'New user registered: {email}')
        flash('Registration successful! Please login.')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/verify-email/<token>')
def verify_email(token):
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user = User.query.filter_by(email=data['email']).first()
        if user:
            user.email_verified = True
            db.session.commit()
            logger.info(f'Email verified for user: {user.email}')
            flash('Email verified successfully')
        return redirect(url_for('login'))
    except:
        flash('Invalid or expired verification link')
        return redirect(url_for('login'))

@app.route('/verify-phone', methods=['POST'])
@login_required
def verify_phone():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    code = request.form.get('code')
    if code == current_user.verification_code:
        current_user.phone_verified = True
        db.session.commit()
        logger.info(f'Phone verified for user: {current_user.email}')
        flash('Phone verified successfully')
    else:
        flash('Invalid verification code')
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Find user by username or email
        user = User.query.filter(
            (User.username == username) | (User.email == username)
        ).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Logged in successfully!')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username/email or password')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    # Clear chat history from session before logging out
    session.pop('chat_history', None)
    logout_user()
    flash('Logged out successfully!')
    return redirect(url_for('index'))

@app.route('/sso/google')
def google_login():
    # Google OAuth2 implementation
    return redirect(url_for('dashboard'))

@app.route('/sso/facebook')
def facebook_login():
    # Facebook OAuth2 implementation
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
@login_required
def dashboard():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    
    return render_template('dashboard.html', 
                         username=current_user.username)

@app.route('/backup', methods=['POST'])
@login_required
def create_backup():
    try:
        result = perform_backup_operation('create')
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/restore/<backup_type>/<filename>')
@login_required
def restore_backup(backup_type, filename):
    try:
        result = perform_backup_operation('restore', backup_type, filename)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/delete-backup/<backup_type>/<filename>', methods=['DELETE'])
@login_required
def delete_backup(backup_type, filename):
    try:
        result = perform_backup_operation('delete', backup_type, filename)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/list-backups')
@login_required
def list_backups():
    try:
        backups = {
            'database': [],
            'chat_history': [],
            'user_data': []
        }
        
        for backup_type in backups.keys():
            backup_dir = os.path.join('backups', backup_type)
            if os.path.exists(backup_dir):
                files = os.listdir(backup_dir)
                for file in files:
                    file_path = os.path.join(backup_dir, file)
                    stat = os.stat(file_path)
                    backups[backup_type].append({
                        'filename': file,
                        'size': stat.st_size,
                        'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                        'modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
                    })
                
                backups[backup_type].sort(key=lambda x: x['created'], reverse=True)
        
        return jsonify(backups)
    except Exception as e:
        logger.error(f'Error listing backups: {str(e)}')
        return jsonify({'error': str(e)}), 500

@app.route('/enroll-voice', methods=['POST'])
@login_required
def enroll_voice():
    try:
        if 'audio' not in request.files:
            return jsonify({'error': 'No audio file provided'}), 400
            
        audio_file = request.files['audio']
        if audio_file.filename == '':
            return jsonify({'error': 'No selected file'}), 400

        result = process_voice_audio(audio_file, current_user.id)
        if not result['success']:
            return jsonify({'success': False, 'message': result['error']})
            
        if "i want to use chatbot" in result['text']:  # Simplified phrase
            # Store or update voice authentication
            voice_auth = VoiceAuth.query.filter_by(user_id=current_user.id).first()
            if not voice_auth:
                voice_auth = VoiceAuth(
                    user_id=current_user.id,
                    voice_template=result['voice_data'],
                    voice_hash=result['voice_hash'],
                    is_enrolled=True
                )
                db.session.add(voice_auth)
            else:
                voice_auth.voice_template = result['voice_data']
                voice_auth.voice_hash = result['voice_hash']
                voice_auth.is_enrolled = True
                voice_auth.last_used = datetime.utcnow()
            
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Voice enrolled successfully'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Please speak the enrollment phrase correctly'
            })
                
    except Exception as e:
        logger.error(f'Error in voice enrollment: {str(e)}')
        return jsonify({
            'success': False,
            'message': f'Server error: {str(e)}'
        }), 500

@app.route('/verify-voice', methods=['POST'])
@login_required
def verify_voice():
    try:
        # First check if user has enrolled their voice
        voice_auth = VoiceAuth.query.filter_by(user_id=current_user.id).first()
        if not voice_auth or not voice_auth.is_enrolled:
            return jsonify({
                'success': False,
                'message': 'Please enroll your voice first',
                'needs_enrollment': True
            })

        if 'audio' not in request.files:
            return jsonify({'error': 'No audio file provided'}), 400
            
        audio_file = request.files['audio']
        if audio_file.filename == '':
            return jsonify({'error': 'No selected file'}), 400

        result = process_voice_audio(audio_file, current_user.id)
        if not result['success']:
            return jsonify({'success': False, 'message': result['error']})
            
        # Compare voice characteristics with stored template
        voice_match = compare_voice_characteristics(result['voice_data'], voice_auth.voice_template)
        
        if voice_match and "i want to use chatbot" in result['text']:  # Simplified phrase
            # Update last used timestamp
            voice_auth.last_used = datetime.utcnow()
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Voice authentication successful'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Voice authentication failed - voice or phrase not recognized'
            })
                
    except Exception as e:
        logger.error(f'Error in voice verification: {str(e)}')
        return jsonify({
            'success': False,
            'message': f'Server error: {str(e)}'
        }), 500

def compare_voice_characteristics(current_voice_data, stored_template):
    """
    Compare voice characteristics between current sample and stored template.
    In a production system, you would use a proper voice biometric library.
    This is a simplified version for demonstration.
    """
    # For demonstration, we'll do a basic comparison
    # In reality, you'd use a voice biometric library that compares
    # features like pitch, tone, frequency patterns, etc.
    
    current_hash = hashlib.sha256(current_voice_data).hexdigest()
    stored_hash = hashlib.sha256(stored_template).hexdigest()
    
    # Calculate similarity (this is a simplified example)
    similarity = sum(a == b for a, b in zip(current_hash, stored_hash)) / len(current_hash)
    
    # Set a threshold for voice matching
    VOICE_MATCH_THRESHOLD = 0.85
    return similarity >= VOICE_MATCH_THRESHOLD

@app.route('/chatbot')
@login_required
def chatbot():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    
    # Initialize chat history in session if not exists
    if 'chat_history' not in session:
        session['chat_history'] = []
    
    # Get current date and previous dates for chat history
    today = datetime.utcnow().date()
    yesterday = today - timedelta(days=1)
    week_ago = today - timedelta(days=7)
    
    return render_template('chat.html', 
                         username=current_user.username,
                         chat_history=session['chat_history'],
                         today=today,
                         yesterday=yesterday,
                         week_ago=week_ago)

@app.route('/load_chat/<int:chat_id>')
@login_required
def load_chat(chat_id):
    # Get the chat and all related messages
    chat = ChatMessage.query.filter_by(id=chat_id, user_id=current_user.id).first()
    if not chat:
        return jsonify({'error': 'Chat not found'}), 404
        
    # Get all messages from the same conversation
    messages = []
    messages.append({
        'message': chat.message,
        'is_user': True
    })
    messages.append({
        'message': chat.response,
        'is_user': False
    })
    
    return jsonify({'messages': messages})

@app.route('/clear_chat', methods=['POST'])
@login_required
def clear_chat():
    try:
        # Clear chat history from session
        session['chat_history'] = []
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f'Error clearing chat: {str(e)}')
        return jsonify({'success': False, 'error': str(e)})

@app.route('/chat', methods=['POST'])
@login_required
def chat():
    try:
        data = request.get_json()
        user_message = data.get('message', '')
        
        if not user_message:
            return jsonify({'response': 'Please send a message!'})
        
        # Get bot response
        bot_response = get_bot_response(user_message)
        
        # Initialize chat history in session if not exists
        if 'chat_history' not in session:
            session['chat_history'] = []
        
        # Add new message to session chat history
        session['chat_history'].append({
            'message': user_message,
            'response': bot_response,
            'timestamp': datetime.utcnow().isoformat()
        })
        
        # Save to database for persistence
        chat_message = ChatMessage(
            user_id=current_user.id,
            message=user_message,
            response=bot_response
        )
        db.session.add(chat_message)
        db.session.commit()
        
        return jsonify({'response': bot_response})
    except Exception as e:
        logger.error(f'Error in chat route: {str(e)}')
        return jsonify({'response': 'Sorry, there was an error processing your request.'}), 500

@app.route('/backup-manager')
@login_required
def backup_manager():
    return render_template('backup_manager.html')

@app.route('/profile')
@login_required
def profile():
    if not current_user.profile:
        profile = UserProfile(user_id=current_user.id)
        db.session.add(profile)
        db.session.commit()
    return render_template('profile.html', user=current_user)

@app.route('/profile/update', methods=['POST'])
@login_required
def update_profile():
    try:
        profile = current_user.profile
        if not profile:
            profile = UserProfile(user_id=current_user.id)
            db.session.add(profile)

        profile.full_name = request.form.get('full_name')
        profile.bio = request.form.get('bio')
        profile.location = request.form.get('location')
        profile.website = request.form.get('website')

        # Handle avatar upload
        if 'avatar' in request.files:
            avatar = request.files['avatar']
            if avatar.filename:
                # Create uploads directory if it doesn't exist
                upload_dir = os.path.join(app.root_path, 'static', 'uploads', 'avatars')
                os.makedirs(upload_dir, exist_ok=True)
                
                # Generate unique filename
                filename = f"avatar_{current_user.id}_{int(datetime.utcnow().timestamp())}.{avatar.filename.rsplit('.', 1)[1].lower()}"
                filepath = os.path.join(upload_dir, filename)
                
                # Save file
                avatar.save(filepath)
                
                # Update profile with new avatar path
                profile.avatar_path = f"uploads/avatars/{filename}"

        db.session.commit()
        flash('Profile updated successfully!')
        return redirect(url_for('profile'))
    except Exception as e:
        logger.error(f'Error updating profile: {str(e)}')
        flash('Error updating profile. Please try again.')
        return redirect(url_for('profile'))

@app.route('/files')
@login_required
def files():
    user_files = UserFile.query.filter_by(user_id=current_user.id).order_by(UserFile.uploaded_at.desc()).all()
    return render_template('files.html', files=user_files)

@app.route('/upload/<string:upload_type>', methods=['POST'])
@login_required
def upload_handler(upload_type):
    try:
        if 'file' not in request.files:
            flash('No file selected')
            return redirect(url_for(f'{upload_type}s'))
            
        file = request.files['file']
        if file.filename == '':
            flash('No file selected')
            return redirect(url_for(f'{upload_type}s'))
            
        if upload_type == 'file':
            success, message = handle_file_upload(
                file, 
                'files',
                UserFile,
                user_id=current_user.id,
                filename=file.filename,
                file_type=file.content_type
            )
        elif upload_type == 'document':
            case_id = request.form.get('case_id')
            success, message = handle_file_upload(
                file,
                'legal_docs',
                LegalDocument,
                case_id=case_id,
                document_type=request.form.get('document_type'),
                document_number=request.form.get('document_number'),
                filing_date=datetime.utcnow(),
                filed_by=request.form.get('filed_by')
            )
        else:
            flash('Invalid upload type')
            return redirect(url_for('dashboard'))
            
        flash(message)
        return redirect(url_for(f'{upload_type}s', case_id=case_id) if upload_type == 'document' else url_for(f'{upload_type}s'))
    except Exception as e:
        logger.error(f'Error in upload handler: {str(e)}')
        flash('Error uploading file. Please try again.')
        return redirect(url_for('dashboard'))

@app.route('/delete/<string:delete_type>/<int:item_id>', methods=['POST'])
@login_required
def delete_handler(delete_type, item_id):
    try:
        if delete_type == 'file':
            item = UserFile.query.filter_by(id=item_id, user_id=current_user.id).first()
        elif delete_type == 'document':
            item = LegalDocument.query.filter_by(id=item_id).first()
        else:
            flash('Invalid delete type')
            return redirect(url_for('dashboard'))
            
        if not item:
            flash(f'{delete_type.capitalize()} not found')
            return redirect(url_for(f'{delete_type}s'))
            
        file_path = os.path.join(app.root_path, 'static', item.file_path)
        if os.path.exists(file_path):
            os.remove(file_path)
            
        db.session.delete(item)
        db.session.commit()
        
        flash(f'{delete_type.capitalize()} deleted successfully!')
        return redirect(url_for(f'{delete_type}s'))
    except Exception as e:
        logger.error(f'Error deleting {delete_type}: {str(e)}')
        flash(f'Error deleting {delete_type}. Please try again.')
        return redirect(url_for(f'{delete_type}s'))

# Indian Justice System Routes
@app.route('/cases')
@login_required
def list_cases():
    cases = CourtCase.query.order_by(CourtCase.filing_date.desc()).all()
    return render_template('cases.html', cases=cases)

@app.route('/case/<string:cnr_number>')
@login_required
def case_details(cnr_number):
    case = CourtCase.query.filter_by(cnr_number=cnr_number).first_or_404()
    history = CaseHistory.query.filter_by(case_id=case.id).order_by(CaseHistory.hearing_date.desc()).all()
    orders = CourtOrder.query.filter_by(case_id=case.id).order_by(CourtOrder.order_date.desc()).all()
    documents = LegalDocument.query.filter_by(case_id=case.id).all()
    return render_template('case_details.html', case=case, history=history, orders=orders, documents=documents)

@app.route('/advocates')
@login_required
def list_advocates():
    advocates = Advocate.query.order_by(Advocate.name).all()
    return render_template('advocates.html', advocates=advocates)

@app.route('/advocate/<string:registration_number>')
@login_required
def advocate_details(registration_number):
    advocate = Advocate.query.filter_by(registration_number=registration_number).first_or_404()
    return render_template('advocate_details.html', advocate=advocate)

@app.route('/courts')
@login_required
def list_courts():
    courts = Court.query.order_by(Court.court_type, Court.state).all()
    return render_template('courts.html', courts=courts)

@app.route('/court/<int:court_id>')
@login_required
def court_details(court_id):
    court = Court.query.get_or_404(court_id)
    judges = Judge.query.filter_by(court_id=court_id).all()
    cause_lists = CauseLists.query.filter_by(court_id=court_id).order_by(CauseLists.hearing_date.desc()).limit(10).all()
    return render_template('court_details.html', court=court, judges=judges, cause_lists=cause_lists)

@app.route('/acts')
@login_required
def list_acts():
    acts = LegalAct.query.order_by(LegalAct.year.desc(), LegalAct.act_name).all()
    return render_template('acts.html', acts=acts)

@app.route('/act/<int:act_id>')
@login_required
def act_details(act_id):
    act = LegalAct.query.get_or_404(act_id)
    return render_template('act_details.html', act=act)

@app.route('/fir')
@login_required
def list_fir():
    firs = FIR.query.order_by(FIR.filing_date.desc()).all()
    return render_template('fir_list.html', firs=firs)

@app.route('/fir/<string:fir_number>')
@login_required
def fir_details(fir_number):
    fir = FIR.query.filter_by(fir_number=fir_number).first_or_404()
    return render_template('fir_details.html', fir=fir)

@app.route('/case/search', methods=['GET', 'POST'])
@login_required
def search_cases():
    if request.method == 'POST':
        search_term = request.form.get('search_term')
        search_type = request.form.get('search_type')
        
        if search_type == 'cnr':
            cases = CourtCase.query.filter_by(cnr_number=search_term).all()
        elif search_type == 'party':
            cases = CourtCase.query.filter(
                (CourtCase.petitioner_name.ilike(f'%{search_term}%')) |
                (CourtCase.respondent_name.ilike(f'%{search_term}%'))
            ).all()
        elif search_type == 'advocate':
            cases = CourtCase.query.filter(
                CourtCase.advocate_name.ilike(f'%{search_term}%')
            ).all()
        else:
            cases = []
            
        return render_template('search_results.html', cases=cases, search_term=search_term)
    
    return render_template('search_cases.html')

@app.route('/cause-lists')
@login_required
def cause_lists():
    today = datetime.utcnow().date()
    lists = CauseLists.query.filter(
        CauseLists.hearing_date >= today
    ).order_by(CauseLists.hearing_date).all()
    return render_template('cause_lists.html', lists=lists)

@app.route('/judges')
@login_required
def list_judges():
    judges = Judge.query.join(Court).order_by(Court.court_type, Judge.name).all()
    return render_template('judges.html', judges=judges)

@app.route('/documents/<int:case_id>')
@login_required
def case_documents(case_id):
    case = CourtCase.query.get_or_404(case_id)
    documents = LegalDocument.query.filter_by(case_id=case_id).all()
    return render_template('case_documents.html', case=case, documents=documents)

@app.route('/upload-document/<int:case_id>', methods=['POST'])
@login_required
def upload_document(case_id):
    try:
        if 'document' not in request.files:
            flash('No document selected')
            return redirect(url_for('case_documents', case_id=case_id))
            
        file = request.files['document']
        if file.filename == '':
            flash('No document selected')
            return redirect(url_for('case_documents', case_id=case_id))
            
        # Create uploads directory if it doesn't exist
        upload_dir = os.path.join(app.root_path, 'static', 'uploads', 'legal_docs')
        os.makedirs(upload_dir, exist_ok=True)
        
        # Generate unique filename
        filename = f"{int(datetime.utcnow().timestamp())}_{file.filename}"
        filepath = os.path.join(upload_dir, filename)
        
        # Save file
        file.save(filepath)
        
        # Create document entry
        document = LegalDocument(
            case_id=case_id,
            document_type=request.form.get('document_type'),
            document_number=request.form.get('document_number'),
            filing_date=datetime.utcnow(),
            filed_by=request.form.get('filed_by'),
            document_path=f"uploads/legal_docs/{filename}"
        )
        db.session.add(document)
        db.session.commit()
        
        flash('Document uploaded successfully!')
        return redirect(url_for('case_documents', case_id=case_id))
    except Exception as e:
        logger.error(f'Error uploading document: {str(e)}')
        flash('Error uploading document. Please try again.')
        return redirect(url_for('case_documents', case_id=case_id))

if __name__ == '__main__':
    # Create database tables
    with app.app_context():
        db.create_all()  # Create new tables
    app.run(debug=True)
