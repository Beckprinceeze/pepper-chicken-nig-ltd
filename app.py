import os
import logging
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from forms import LoginForm

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Create Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "pepper-chicken-secret-key")

# Setup Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'admin_login'  # type: ignore
login_manager.login_message = "Please log in to access the admin area."
login_manager.login_message_category = "warning"  # type: ignore

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Hard-coded admin user (in a real app, this would be stored in a database)
admin_user = User(
    id=1, 
    username='admin',
    password_hash=generate_password_hash('pepperchicken2023')
)

users = {
    'admin': admin_user
}

@login_manager.user_loader
def load_user(user_id):
    if int(user_id) == 1:
        return admin_user
    return None

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/menu')
def menu():
    return render_template('menu.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

# Admin routes
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if current_user.is_authenticated:
        return redirect(url_for('admin_dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        remember = form.remember.data
        
        user = None
        if username:
            user = users.get(username)  # type: ignore
        
        if user and user.check_password(password):
            login_user(user, remember=remember)
            flash('Login successful!', 'success')
            
            # Redirect to the page they were trying to access or dashboard
            next_page = request.args.get('next')
            return redirect(next_page or url_for('admin_dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('admin/login.html', form=form)

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    return render_template('admin/dashboard.html')

@app.route('/admin/logout')
@login_required
def admin_logout():
    logout_user()
    flash('You have been logged out', 'success')
    return redirect(url_for('index'))

# Ensure running on the right host and port if main script
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
