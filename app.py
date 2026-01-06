import webbrowser
from threading import Timer
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'super-secret-home-hub-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///home.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# --- MODELS ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    chores = db.relationship('Chore', backref='owner', lazy=True)
    expenses = db.relationship('Expense', backref='owner', lazy=True)

class Chore(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task = db.Column(db.String(100), nullable=False)
    assigned_to = db.Column(db.String(50))
    is_done = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item = db.Column(db.String(100), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- ROUTES ---
@app.route('/')
@login_required
def index():
    chores = Chore.query.filter_by(user_id=current_user.id).all()
    expenses = Expense.query.filter_by(user_id=current_user.id).all()
    total_spent = sum(e.amount for e in expenses)
    pending_tasks = Chore.query.filter_by(user_id=current_user.id, is_done=False).count()
    return render_template('index.html', chores=chores, expenses=expenses, total=total_spent, pending=pending_tasks)

@app.route('/add_chore', methods=['POST'])
@login_required
def add_chore():
    db.session.add(Chore(task=request.form.get('task'), assigned_to=request.form.get('person'), user_id=current_user.id))
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/toggle_chore/<int:id>')
@login_required
def toggle_chore(id):
    chore = Chore.query.get_or_404(id)
    if chore.user_id == current_user.id:
        chore.is_done = not chore.is_done
        db.session.commit()
    return redirect(url_for('index'))

@app.route('/delete_chore/<int:id>')
@login_required
def delete_chore(id):
    chore = Chore.query.get_or_404(id)
    if chore.user_id == current_user.id:
        db.session.delete(chore)
        db.session.commit()
    return redirect(url_for('index'))

@app.route('/add_expense', methods=['POST'])
@login_required
def add_expense():
    db.session.add(Expense(item=request.form.get('item'), amount=float(request.form.get('amount')), user_id=current_user.id))
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/delete_expense/<int:id>')
@login_required
def delete_expense(id):
    exp = Expense.query.get_or_404(id)
    if exp.user_id == current_user.id:
        db.session.delete(exp)
        db.session.commit()
    return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('username')).first()
        if user and check_password_hash(user.password, request.form.get('password')):
            login_user(user)
            return redirect(url_for('index'))
        flash('Login failed!', 'danger')
    return render_template('auth.html', mode='login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        hashed = generate_password_hash(request.form.get('password'), method='pbkdf2:sha256')
        db.session.add(User(username=request.form.get('username'), password=hashed))
        db.session.commit()
        flash('Success!', 'success')
        return redirect(url_for('login'))
    return render_template('auth.html', mode='register')

@app.route('/logout')
def logout():
    logout_user(); return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context(): db.create_all()
    Timer(1, lambda: webbrowser.open("http://127.0.0.1:5000")).start()
    app.run(debug=True, use_reloader=False)