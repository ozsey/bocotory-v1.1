import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_bootstrap import Bootstrap
from pymongo import MongoClient, ASCENDING
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from dotenv import load_dotenv
from bson import ObjectId
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField
from wtforms.validators import DataRequired, Email, Length

class RegistrationForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    role = SelectField('Role', choices=[('admin', 'Admin'), ('manager', 'Manager'), ('staff', 'Staff')], validators=[DataRequired()])

load_dotenv()
SECRET_KEY = os.getenv('SECRET_KEY')
MONGO_URI = os.getenv('MONGO_URI')

app = Flask(__name__)
app.secret_key = SECRET_KEY
Bootstrap(app)

client = MongoClient(MONGO_URI)
db = client['bocotory']
db.users.create_index([('username', ASCENDING)], unique=True)

ROLE_ADMIN = 'admin'
ROLE_MANAGER = 'manager'
ROLE_STAFF = 'staff'

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'username' not in session:
                flash('Please log in to access this page.', 'error')
                return redirect(url_for('login', next=request.url))
            user = db.users.find_one({'username': session['username']})
            if not user or user['role'] not in roles or user['status'] != 'active':
                flash('Access denied. You do not have permission to access this page.', 'error')
                return redirect(url_for('home'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def get_current_user():
    return db.users.find_one({'username': session['username']}) if 'username' in session else None

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = db.users.find_one({'username': username})

        if user and check_password_hash(user['password'], password) and user['status'] == 'active':
            session['username'] = username
            next_page = request.args.get('next')
            if user['role'] == ROLE_ADMIN:
                return redirect(next_page or url_for('admin_dashboard'))
            elif user['role'] == ROLE_MANAGER:
                return redirect(next_page or url_for('manager_dashboard'))
            elif user['role'] == ROLE_STAFF:
                return redirect(next_page or url_for('staff_dashboard'))
            else:
                flash('Invalid user role.', 'error')
        else:
            flash('Invalid credentials or account not active.', 'error')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        # Proses data masukan setelah divalidasi
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = generate_password_hash(form.password.data)
        role = form.role.data
        status = 'pending'

        if db.users.find_one({'username': username}):
            flash('Username already exists. Please choose a different username.', 'error')
        else:
            db.users.insert_one({
                'name': name,
                'email': email,
                'username': username,
                'password': password,
                'role': role,
                'status': status
            })
            flash('Registration successful. Awaiting admin approval.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/manage_profile', methods=['GET', 'POST'])
@login_required
@role_required(ROLE_ADMIN, ROLE_MANAGER, ROLE_STAFF)
def manage_profile():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        user = db.users.find_one({'username': session['username']})
        db.users.update_one({'username': session['username']}, {
            '$set': {
                'name': name,
                'email': email,
                'password': generate_password_hash(password) if password else user['password']
            }
        })
        flash('Profile updated successfully.', 'success')
        return redirect(url_for('manage_profile'))
    return render_template('manage_profile.html', user=get_current_user())

@app.route('/manage_user', methods=['GET'])
@login_required
@role_required(ROLE_ADMIN)
def manage_user():
    users = list(db.users.find({}, {'password': 0}))  # Exclude password field
    return render_template('manage_user.html', users=users)

@app.route('/add_user', methods=['POST'])
@login_required
@role_required(ROLE_ADMIN)
def add_user():
    data = request.form
    name = data['name']
    email = data['email']
    username = data['username']
    password = generate_password_hash(data['password'])
    role = data['role']
    status = data['status']
    
    if db.users.find_one({'username': username}):
        return jsonify({'message': 'Username already exists. Please choose a different username.'}), 400
    
    db.users.insert_one({
        'name': name,
        'email': email,
        'username': username,
        'password': password,
        'role': role,
        'status': status
    })
    return jsonify({'message': 'User added successfully.'}), 200

@app.route('/update_user/<username>', methods=['POST'])
@login_required
@role_required(ROLE_ADMIN)
def update_user(username):
    data = request.form
    name = data['name']
    email = data['email']
    password = generate_password_hash(data['password'])
    role = data['role']
    status = data['status']
    
    db.users.update_one({'username': username}, {
        '$set': {
            'name': name,
            'email': email,
            'password': password,
            'role': role,
            'status': status
        }
    })
    return jsonify({'message': 'User updated successfully.'}), 200

@app.route('/delete_user/<username>', methods=['POST'])
@login_required
@role_required(ROLE_ADMIN)
def delete_user(username):
    db.users.delete_one({'username': username})
    return jsonify({'message': 'User deleted successfully.'}), 200

@app.route('/manage_staff')
@login_required
@role_required(ROLE_ADMIN, ROLE_MANAGER)
def manage_staff():
    staff = list(db.users.find({'role': ROLE_STAFF}, {'password': 0}))  # Exclude password field
    return render_template('manage_staff.html', staff=staff)

@app.route('/update_staff_status/<username>', methods=['POST'])
@login_required
@role_required(ROLE_ADMIN, ROLE_MANAGER)
def update_staff_status(username):
    status = request.form['status']
    db.users.update_one({'username': username}, {'$set': {'status': status}})
    return jsonify({'message': f'Staff status updated to {status}.'}), 200

@app.route('/delete_staff/<username>', methods=['POST'])
@login_required
@role_required(ROLE_ADMIN, ROLE_MANAGER)
def delete_staff(username):
    db.users.delete_one({'username': username})
    return jsonify({'message': 'Staff deleted successfully.'}), 200

@app.route('/manage_storage')
@login_required
@role_required(ROLE_ADMIN, ROLE_MANAGER, ROLE_STAFF)
def manage_storage():
    storage = list(db.storage.find())
    return render_template('manage_storage.html', storage=storage)

@app.route('/add_storage', methods=['POST'])
@login_required
@role_required(ROLE_ADMIN, ROLE_MANAGER, ROLE_STAFF)
def add_storage():
    data = request.form
    storageid = data['storageid']
    location = data['location']
    capacity = data['capacity']

    if db.storage.find_one({'storageid': storageid}):
        return jsonify({'message': 'Storage ID already exists. Please choose a different ID.'}), 400
    
    db.storage.insert_one({
        'storageid': storageid,
        'location': location,
        'capacity': capacity
    })
    return jsonify({'message': 'Storage added successfully.'}), 200

@app.route('/update_storage/<storageid>', methods=['POST'])
@login_required
@role_required(ROLE_ADMIN, ROLE_MANAGER, ROLE_STAFF)
def update_storage(storageid):
    data = request.form
    location = data['location']
    capacity = data['capacity']

    db.storage.update_one({'storageid': storageid}, {
        '$set': {
            'location': location,
            'capacity': capacity
        }
    })
    return jsonify({'message': 'Storage updated successfully.'}), 200

@app.route('/delete_storage/<storageid>', methods=['POST'])
@login_required
@role_required(ROLE_ADMIN, ROLE_MANAGER, ROLE_STAFF)
def delete_storage(storageid):
    db.storage.delete_one({'storageid': storageid})
    return jsonify({'message': 'Storage deleted successfully.'}), 200

@app.route('/manage_stock')
@login_required
@role_required(ROLE_ADMIN, ROLE_MANAGER, ROLE_STAFF)
def manage_stock():
    stocks = list(db.stocks.find())
    return render_template('manage_stock.html', stocks=stocks)

@app.route('/add_stock', methods=['POST'])
@login_required
@role_required(ROLE_ADMIN, ROLE_MANAGER, ROLE_STAFF)
def add_stock():
    data = request.form
    storageid = data['storageid']
    item_name = data['item_name']
    quantity = int(data['quantity'])
    status = data['status']

    storage_capacity = db.storage.find_one({'storageid': storageid}, {'capacity': 1})
    if storage_capacity:
        available_capacity = int(storage_capacity['capacity']) - quantity
        if available_capacity < 0:
            return jsonify({'message': 'Quantity exceeds storage capacity.'}), 400
    else:
        return jsonify({'message': 'Storage ID not found.'}), 404

    if db.stocks.find_one({'storageid': storageid, 'item_name': item_name}):
        return jsonify({'message': 'Stock for this item already exists in the storage.'}), 400

    db.stocks.insert_one({
        'storageid': storageid,
        'item_name': item_name,
        'quantity': quantity,
        'status': status
    })
    return jsonify({'message': 'Stock added successfully.'}), 200

@app.route('/update_stock/<stock_id>', methods=['POST'])
@login_required
@role_required(ROLE_ADMIN, ROLE_MANAGER, ROLE_STAFF)
def update_stock(stock_id):
    data = request.form
    quantity = int(data['quantity'])
    status = data['status']

    stock = db.stocks.find_one({'_id': ObjectId(stock_id)})
    if not stock:
        return jsonify({'message': 'Stock not found.'}), 404

    old_quantity = stock['quantity']
    new_quantity = quantity - old_quantity
    storageid = stock['storageid']

    storage_capacity = db.storage.find_one({'storageid': storageid}, {'capacity': 1})
    if storage_capacity:
        available_capacity = int(storage_capacity['capacity']) - new_quantity
        if available_capacity < 0:
            return jsonify({'message': 'Quantity update exceeds storage capacity.'}), 400
    else:
        return jsonify({'message': 'Storage ID not found.'}), 404

    db.stocks.update_one({'_id': ObjectId(stock_id)}, {
        '$set': {
            'quantity': quantity,
            'status': status
        }
    })
    return jsonify({'message': 'Stock updated successfully.'}), 200

@app.route('/delete_stock/<stock_id>', methods=['POST'])
@login_required
@role_required(ROLE_ADMIN, ROLE_MANAGER, ROLE_STAFF)
def delete_stock(stock_id):
    stock = db.stocks.find_one({'_id': ObjectId(stock_id)})
    if not stock:
        return jsonify({'message': 'Stock not found.'}), 404

    db.stocks.delete_one({'_id': ObjectId(stock_id)})
    return jsonify({'message': 'Stock deleted successfully.'}), 200

@app.route('/manage_supplier')
@login_required
@role_required(ROLE_ADMIN, ROLE_MANAGER, ROLE_STAFF)
def manage_supplier():
    suppliers = list(db.suppliers.find())
    return render_template('manage_supplier.html', suppliers=suppliers)

@app.route('/add_supplier', methods=['POST'])
@login_required
@role_required(ROLE_ADMIN, ROLE_MANAGER, ROLE_STAFF)
def add_supplier():
    data = request.form
    name = data['name']
    address = data['address']
    contact = data['contact']

    if db.suppliers.find_one({'name': name}):
        return jsonify({'message': 'Supplier with this name already exists.'}), 400

    db.suppliers.insert_one({
        'name': name,
        'address': address,
        'contact': contact
    })
    return jsonify({'message': 'Supplier added successfully.'}), 200

@app.route('/update_supplier/<supplier_id>', methods=['POST'])
@login_required
@role_required(ROLE_ADMIN, ROLE_MANAGER, ROLE_STAFF)
def update_supplier(supplier_id):
    data = request.form
    name = data['name']
    address = data['address']
    contact = data['contact']

    db.suppliers.update_one({'_id': ObjectId(supplier_id)}, {
        '$set': {
            'name': name,
            'address': address,
            'contact': contact
        }
    })
    return jsonify({'message': 'Supplier updated successfully.'}), 200

@app.route('/delete_supplier/<supplier_id>', methods=['POST'])
@login_required
@role_required(ROLE_ADMIN, ROLE_MANAGER, ROLE_STAFF)
def delete_supplier(supplier_id):
    db.suppliers.delete_one({'_id': ObjectId(supplier_id)})
    return jsonify({'message': 'Supplier deleted successfully.'}), 200

""" @app.route('/manage_dashboard')
@login_required
def dashboard():
    return render_template('manage_dashboard.html', user=get_current_user()) """

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login'))

@app.route('/admin_dashboard')
@login_required
@role_required(ROLE_ADMIN)
def admin_dashboard():
    return render_template('base.html', user=get_current_user())

@app.route('/manager_dashboard')
@login_required
@role_required(ROLE_MANAGER)
def manager_dashboard():
    return render_template('base.html', user=get_current_user())

@app.route('/staff_dashboard')
@login_required
@role_required(ROLE_STAFF)
def staff_dashboard():
    return render_template('base.html', user=get_current_user())

if __name__ == '__main__':
    app.run(debug=True)