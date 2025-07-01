from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import bcrypt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- User Model ---
class UserModel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    jobs = db.relationship('JobModel', backref='user', cascade="all, delete", lazy=True)

# --- Job Model ---
class JobModel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_name = db.Column(db.String(100), nullable=False)
    file_path = db.Column(db.String(255), nullable=False)
    priority = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user_model.id'), nullable=False)

# --- Registration Endpoint ---
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

# --- Login Endpoint ---
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = UserModel.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': 'Invalid username or password'}), 401

    if bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
        return jsonify({'message': 'Login successful'}), 200
    else:
        return jsonify({'error': 'Invalid username or password'}), 401

@app.route('/sync_jobs/<username>', methods=['POST'])
def replace_jobs(username):
    user = UserModel.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    job_list = request.get_json()

    if not isinstance(job_list, list):
        return jsonify({'error': 'Expected a list of jobs'}), 400

    # Delete existing jobs for this user
    JobModel.query.filter_by(user_id=user.id).delete()

    for job in job_list:
        file_name = job.get('file_name')
        file_path = job.get('file_path')
        priority = job.get('priority')

        if not file_name or not file_path or priority is None:
            return jsonify({'error': 'Each job must have file_name, file_path, and priority'}), 400

        new_job = JobModel(
            file_name=file_name,
            file_path=file_path,
            priority=priority,
            user_id=user.id
        )
        db.session.add(new_job)

    db.session.commit()
    return jsonify({'message': 'Jobs replaced successfully'}), 200

@app.route('/sync_jobs/<username>', methods=['GET'])
def get_jobs(username):
    user = UserModel.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    jobs = JobModel.query.filter_by(user_id=user.id).order_by(JobModel.priority).all()

    jobs_json = [
        {
            'file_name': job.file_name,
            'file_path': job.file_path,
            'priority': job.priority
        }
        for job in jobs
    ]

    return jsonify(jobs_json), 200

# --- Initialize Database ---
with app.app_context():
    db.create_all()

# --- Run Server ---
if __name__ == '__main__':
    app.run(debug=True)