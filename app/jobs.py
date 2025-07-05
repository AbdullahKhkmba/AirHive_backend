from flask import Blueprint, request, jsonify, send_file
from flask_jwt_extended import jwt_required, get_jwt_identity
from app import db
from app.models import JobModel, UserModel
import io

jobs_bp = Blueprint('jobs', __name__)

# --- Sync Jobs (Add, Update, Delete) ---
@jobs_bp.route('/sync_jobs', methods=['POST'])
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

    # Fetch existing jobs
    existing_jobs = JobModel.query.filter_by(user_id=user.id).all()
    existing_job_map = {job.file_path: job for job in existing_jobs}

    to_add = []
    to_keep = []
    to_delete = []

    for file_path, job_data in incoming_job_map.items():
        if file_path in existing_job_map:
            to_keep.append(file_path)
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

    for file_path, job in existing_job_map.items():
        if file_path not in incoming_job_map:
            to_delete.append(job)

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
        'updated': len(to_keep)
    }), 200

# --- Get Jobs ---
@jobs_bp.route('/sync_jobs', methods=['GET'])
@jwt_required()
def get_jobs():
    user_id = get_jwt_identity()
    jobs = JobModel.query.filter_by(user_id=user_id).order_by(JobModel.priority).all()

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

# --- Upload File ---
@jobs_bp.route('/upload_file/<int:job_id>', methods=['PUT'])
@jwt_required()
def upload_file(job_id):
    user_id = get_jwt_identity()
    job = JobModel.query.get(job_id)

    if not job or job.user_id != user_id:
        return jsonify({'error': 'Job not found or does not belong to user'}), 404

    if 'file' not in request.files:
        return jsonify({'error': 'No file part in request'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    job.file_data = file.read()
    db.session.commit()
    return jsonify({'message': 'File uploaded successfully'}), 200

# --- Download File ---
@jobs_bp.route('/download_file/<int:job_id>', methods=['GET'])
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