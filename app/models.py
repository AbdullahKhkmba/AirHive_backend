from app import db

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

    __table_args__ = (
        db.UniqueConstraint('user_id', 'file_path', name='uq_user_file_path'),
    )