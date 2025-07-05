from flask import Flask, request, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
import bcrypt
import io

# --- App Config ---
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your_secret_key_here'  # Change in production
db = SQLAlchemy(app)
CORS(app)
jwt = JWTManager(app)

# --- Models ---
class UserModel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    jobs = db.relationship('JobModel', backref='user', cascade="all, delete", lazy=True)

class JobModel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_name = db.Column(db.String(100), nullable=False)
    file_path = db.Column(db.String(255), nullable=False)
    priority = db.Column(db.Integer, nullable=False)
    file_data = db.Column(db.LargeBinary, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user_model.id'), nullable=False)

# --- Routes ---
@app.route('/')
def index():
    return "<h1>Hello from the secure backend</h1>"

# --- Register ---
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    if UserModel.query.filter_by(username=username).first():
        return jsonify({'error': 'Username already exists'}), 409

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    new_user = UserModel(username=username, password=hashed_password.decode('utf-8'))
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201

# --- Login ---
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = UserModel.query.filter_by(username=username).first()
    if not user or not bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
        return jsonify({'error': 'Invalid username or password'}), 401

    access_token = create_access_token(identity=user.id)
    return jsonify({'access_token': access_token}), 200

# --- Send Jobs to the database ---
@app.route('/sync_jobs', methods=['POST'])
@jwt_required()
def replace_jobs():
    user_id = get_jwt_identity()
    user = UserModel.query.get(user_id)

    incoming_jobs = request.get_json()
    if not isinstance(incoming_jobs, list):
        return jsonify({'error': 'Expected a list of jobs'}), 400

    # Validate and map incoming jobs by file_path
    incoming_job_map = {
        job['file_path']: job for job in incoming_jobs
        if job.get('file_name') and job.get('file_path') and job.get('priority') is not None
    }

    if len(incoming_job_map) != len(incoming_jobs):
        return jsonify({'error': 'Each job must have file_name, file_path, and priority'}), 400

    # Fetch all existing jobs for this user
    existing_jobs = JobModel.query.filter_by(user_id=user.id).all()
    existing_job_map = {job.file_path: job for job in existing_jobs}

    to_add = []
    to_keep = []
    to_delete = []

    # Identify new and existing jobs
    for file_path, job_data in incoming_job_map.items():
        if file_path in existing_job_map:
            to_keep.append(file_path)
            # Optional: update priority or file_name if needed
            existing_job = existing_job_map[file_path]
            if (existing_job.file_name != job_data['file_name'] or
                existing_job.priority != job_data['priority']):
                existing_job.file_name = job_data['file_name']
                existing_job.priority = job_data['priority']
        else:
            new_job = JobModel(
                file_name=job_data['file_name'],
                file_path=job_data['file_path'],
                priority=job_data['priority'],
                user_id=user.id
            )
            to_add.append(new_job)

    # Identify jobs to delete
    for file_path, job in existing_job_map.items():
        if file_path not in incoming_job_map:
            to_delete.append(job)

    # Apply changes
    for job in to_add:
        db.session.add(job)
    for job in to_delete:
        db.session.delete(job)

    db.session.commit()

    return jsonify({
        'message': 'Jobs synced successfully',
        'added': len(to_add),
        'deleted': len(to_delete),
        'kept': len(to_keep),
        'updated': len(to_keep)  # optional
    }), 200

# --- Get All Jobs for Logged-in User ---
@app.route('/sync_jobs', methods=['GET'])
@jwt_required()
def get_jobs():
    user_id = get_jwt_identity()
    user = UserModel.query.get(user_id)

    jobs = JobModel.query.filter_by(user_id=user.id).order_by(JobModel.priority).all()
    jobs_json = [
        {
            'id': job.id,
            'file_name': job.file_name,
            'file_path': job.file_path,
            'priority': job.priority,
            'file_exist': job.file_data is not None  
        }
        for job in jobs
    ]

    return jsonify(jobs_json), 200

# --- Upload File to Job ---
@app.route('/upload_file/<int:job_id>', methods=['PUT'])
@jwt_required()
def upload_file(job_id):
    user_id = get_jwt_identity()
    job = JobModel.query.get(job_id)

    if not job or job.user_id != user_id:
        return jsonify({'error': 'Job not found or does not belong to user'}), 404

    if 'file' not in request.files:
        return jsonify({'error': 'No file part in the request'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    job.file_data = file.read()
    db.session.commit()

    return jsonify({'message': 'File uploaded successfully'}), 200

# --- Download File from Job ---
@app.route('/download_file/<int:job_id>', methods=['GET'])
@jwt_required()
def download_file(job_id):
    user_id = get_jwt_identity()
    job = JobModel.query.get(job_id)

    if not job or job.user_id != user_id:
        return jsonify({'error': 'Job not found or does not belong to user'}), 404

    if not job.file_data:
        return jsonify({'error': 'No file uploaded for this job'}), 404

    return send_file(
        io.BytesIO(job.file_data),
        as_attachment=True,
        download_name=job.file_name,
        mimetype='application/octet-stream'
    )

# --- Initialize DB ---
with app.app_context():
    db.create_all()

# --- Run Server ---
if __name__ == '__main__':
    app.run(debug=True)