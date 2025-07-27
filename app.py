from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user,
    login_required, logout_user, current_user,
)
from werkzeug.security import generate_password_hash, check_password_hash
import requests

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///jobportal.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User roles constants
ROLE_JOBSEEKER = 'jobseeker'
ROLE_EMPLOYER = 'employer'
ROLE_ADMIN = 'admin'

# Database Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(50), nullable=False, default=ROLE_JOBSEEKER)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_admin(self):
        return self.role == ROLE_ADMIN

    def is_employer(self):
        return self.role == ROLE_EMPLOYER

    def is_jobseeker(self):
        return self.role == ROLE_JOBSEEKER


class Job(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    salary = db.Column(db.String(100))
    location = db.Column(db.String(100))
    category = db.Column(db.String(100))  # New field
    company = db.Column(db.String(100))   # New field
    employer_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    employer = db.relationship('User', backref='posted_jobs')


class Application(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    job_id = db.Column(db.Integer, db.ForeignKey('job.id'))

    applicant = db.relationship('User', backref='applications')
    job = db.relationship('Job', backref='applications')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Decorator for role-based access
def role_required(*roles):
    def wrapper(f):
        from functools import wraps
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            if current_user.role not in roles:
                abort(403)  # Forbidden
            return f(*args, **kwargs)
        return decorated_function
    return wrapper


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']
        role = request.form.get('role', ROLE_JOBSEEKER)

        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash('Username or email already exists')
            return render_template('register.html')

        if role not in [ROLE_JOBSEEKER, ROLE_EMPLOYER]:
            role = ROLE_JOBSEEKER  # Default fallback

        new_user = User(username=username, email=email, role=role)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please login.')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully!')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!')
    return redirect(url_for('home'))


@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.is_employer():
        user_jobs = Job.query.filter_by(employer_id=current_user.id).all()
        return render_template('dashboard_employer.html', user_jobs=user_jobs)

    elif current_user.is_jobseeker():
        user_apps = Application.query.filter_by(user_id=current_user.id).all()
        return render_template('dashboard_jobseeker.html', user_apps=user_apps)

    elif current_user.is_admin():
        all_users = User.query.all()
        all_jobs = Job.query.all()
        return render_template('dashboard_admin.html', users=all_users, jobs=all_jobs)

    else:
        flash("Unknown role. Contact admin.")
        return redirect(url_for('home'))


@app.route('/post-job', methods=['GET', 'POST'])
@login_required
@role_required(ROLE_EMPLOYER)
def post_job():
    if request.method == 'POST':
        title = request.form['title'].strip()
        description = request.form['description'].strip()
        salary = request.form['salary'].strip()
        location = request.form['location'].strip()
        company = request.form['company'].strip()
        category = request.form['category'].strip()

        new_job = Job(
            title=title, description=description, salary=salary,
            location=location, company=company, category=category,
            employer_id=current_user.id
        )
        db.session.add(new_job)
        db.session.commit()
        flash('Job posted successfully!')
        return redirect(url_for('dashboard'))
    return render_template('post_job.html')


@app.route('/edit-job/<int:job_id>', methods=['GET', 'POST'])
@login_required
def edit_job(job_id):
    job = Job.query.get_or_404(job_id)

    # Only the employer who posted the job or admin can edit
    if job.employer_id != current_user.id and not current_user.is_admin():
        abort(403)  # Forbidden

    if request.method == 'POST':
        job.title = request.form['title'].strip()
        job.description = request.form['description'].strip()
        job.salary = request.form['salary'].strip()
        job.location = request.form['location'].strip()
        job.company = request.form['company'].strip()
        job.category = request.form['category'].strip()
        db.session.commit()
        flash('Job updated successfully!')
        return redirect(url_for('dashboard'))

    return render_template('edit_job.html', job=job)


@app.route('/delete-job/<int:job_id>', methods=['POST'])
@login_required
def delete_job(job_id):
    job = Job.query.get_or_404(job_id)

    # Only the employer who posted the job or admin can delete
    if job.employer_id != current_user.id and not current_user.is_admin():
        abort(403)  # Forbidden

    db.session.delete(job)
    db.session.commit()
    flash('Job deleted successfully!')
    return redirect(url_for('dashboard'))


@app.route('/jobs')
def jobs():
    location = request.args.get('location', '').strip()
    title = request.args.get('title', '').strip()
    category = request.args.get('category', '').strip()
    company = request.args.get('company', '').strip()

    query = Job.query
    if location:
        query = query.filter(Job.location.ilike(f'%{location}%'))
    if title:
        query = query.filter(Job.title.ilike(f'%{title}%'))
    if category:
        query = query.filter(Job.category.ilike(f'%{category}%'))
    if company:
        query = query.filter(Job.company.ilike(f'%{company}%'))

    jobs_list = query.all()

    # External jobs (optional)
    external_jobs = []
    use_external = request.args.get('external', 'no').lower() == 'yes'
    if use_external:
        try:
            response = requests.get('https://remotive.io/api/remote-jobs')
            if response.ok:
                data = response.json()
                external_jobs = [{
                    'title': job['title'],
                    'description': job['description'],
                    'salary': job.get('salary', 'N/A'),
                    'location': job.get('candidate_required_location', 'Remote'),
                    'external': True,
                    'url': job.get('url'),
                } for job in data.get('jobs', [])]
        except Exception:
            flash('Failed to fetch external jobs.')

    return render_template('jobs.html', jobs=jobs_list, external_jobs=external_jobs,
                           filter_location=location, filter_title=title,
                           filter_category=category, filter_company=company,
                           use_external=use_external)


@app.route('/apply/<int:job_id>', methods=['GET', 'POST'])
@login_required
@role_required(ROLE_JOBSEEKER)
def apply(job_id):
    job = Job.query.get_or_404(job_id)

    existing_application = Application.query.filter_by(user_id=current_user.id, job_id=job.id).first()
    if existing_application:
        flash('You have already applied for this job.')
        return redirect(url_for('jobs'))

    if request.method == 'POST':
        application = Application(user_id=current_user.id, job_id=job.id)
        db.session.add(application)
        db.session.commit()
        flash('Application submitted successfully!')
        return redirect(url_for('dashboard'))

    return render_template('apply.html', job=job)


@app.route('/admin/delete-user/<int:user_id>', methods=['POST'])
@login_required
@role_required(ROLE_ADMIN)
def admin_delete_user(user_id):
    if current_user.id == user_id:
        flash("You cannot delete yourself!")
        return redirect(url_for('dashboard'))

    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash("User deleted successfully.")
    return redirect(url_for('dashboard'))


@app.route('/admin/delete-job/<int:job_id>', methods=['POST'])
@login_required
@role_required(ROLE_ADMIN)
def admin_delete_job(job_id):
    job = Job.query.get_or_404(job_id)
    db.session.delete(job)
    db.session.commit()
    flash("Job deleted successfully.")
    return redirect(url_for('dashboard'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
