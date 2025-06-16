from flask import Blueprint, request, render_template, redirect, url_for, flash, session, jsonify, current_app, send_file
from models.user import db, User, Machine, Item, AccessLog, Withdrawal, Notification
from models.machine import init_machines
import bcrypt
import jwt
from datetime import datetime, timedelta
from sqlalchemy.exc import IntegrityError
from sqlalchemy import inspect, func, extract
import pandas as pd
from werkzeug.utils import secure_filename
import os
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from io import BytesIO
import json
import logging

auth_bp = Blueprint('auth', __name__)

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

ALLOWED_EXTENSIONS = {'xlsx', 'xls'}
ALLOWED_PHOTO_EXTENSIONS = {'jpg', 'jpeg', 'png'}
MAX_PHOTO_SIZE = 5 * 1024 * 1024  # 5MB

def allowed_file(filename, allowed_extensions):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

def create_notification(item, old_status, new_status):
    if old_status != new_status:
        message = f"Item {item.item_number} ({item.name}) status changed from {old_status.capitalize()} to {new_status.capitalize()}"
        notification = Notification(
            item_id=item.id,
            old_status=old_status,
            new_status=new_status,
            message=message,
            timestamp=datetime.utcnow()
        )
        db.session.add(notification)
        logger.info(f"Notification created: {message}")
def get_quarterly_consumption(user_id, role, year=None, quarter=None, category=None, sub_category=None, machine_id=None, item_number=None):
    """Calculate quarterly consumption with advanced filtering."""
    logger.debug(f"Calculating consumption: user_id={user_id}, role={role}, year={year}, quarter={quarter}, category={category}, sub_category={sub_category}, machine_id={machine_id}, item_number={item_number}")
    valid_machine_ids = [m.id for m in Machine.query.all()] if role == 'admin' else [m['id'] for m in session['user']['machines']]
    
    if machine_id:
        machine_id = int(machine_id)
        if machine_id not in valid_machine_ids:
            logger.warning(f"Invalid machine_id: {machine_id}")
            return {'item_consumption': {}, 'machine_consumption': {}, 'category_consumption': {}, 'sub_category_consumption': {}, 'years': [], 'quarters': []}

    query = db.session.query(
        Item.item_number,
        Item.name,
        Item.category,
        Item.sub_category,
        Machine.name.label('machine_name'),
        func.sum(Withdrawal.quantity).label('total_quantity'),
        extract('year', Withdrawal.timestamp).label('year'),
        extract('quarter', Withdrawal.timestamp).label('quarter')
    ).join(Item, Withdrawal.item_id == Item.id
    ).join(Machine, Withdrawal.machine_id == Machine.id
    ).filter(
        Withdrawal.status == 'approved',
        Withdrawal.machine_id.in_(valid_machine_ids)
    )

    if year:
        query = query.filter(extract('year', Withdrawal.timestamp) == year)
    if quarter:
        query = query.filter(extract('quarter', Withdrawal.timestamp) == quarter)
    if category:
        query = query.filter(Item.category == category)
    if sub_category:
        query = query.filter(Item.sub_category == sub_category)
    if machine_id:
        query = query.filter(Withdrawal.machine_id == machine_id)
    if item_number:
        query = query.filter(Item.item_number.ilike(f'%{item_number}%'))

    query = query.group_by(
        Item.item_number, Item.name, Item.category, Item.sub_category, Machine.name, 'year', 'quarter'
    )

    results = query.all()
    logger.debug(f"Raw query results: {[(r.item_number, r.total_quantity, r.year, r.quarter) for r in results]}")

    item_consumption = {}
    machine_consumption = {}
    category_consumption = {}
    sub_category_consumption = {}
    years = set()
    quarters = set()

    for row in results:
        item_key = f"{row.item_number} - {row.name}"
        quarter_key = f"Q{int(row.quarter)}-{int(row.year)}"
        years.add(int(row.year))
        quarters.add(f"Q{int(row.quarter)}-{int(row.year)}")

        # Item consumption
        if item_key not in item_consumption:
            item_consumption[item_key] = {}
        item_consumption[item_key][quarter_key] = item_consumption[item_key].get(quarter_key, 0) + row.total_quantity

        # Machine consumption
        if row.machine_name not in machine_consumption:
            machine_consumption[row.machine_name] = {}
        machine_consumption[row.machine_name][quarter_key] = machine_consumption[row.machine_name].get(quarter_key, 0) + row.total_quantity

        # Category consumption
        if row.category not in category_consumption:
            category_consumption[row.category] = {}
        category_consumption[row.category][quarter_key] = category_consumption[row.category].get(quarter_key, 0) + row.total_quantity

        # Sub-category consumption
        if row.sub_category:
            if row.sub_category not in sub_category_consumption:
                sub_category_consumption[row.sub_category] = {}
            sub_category_consumption[row.sub_category][quarter_key] = sub_category_consumption[row.sub_category].get(quarter_key, 0) + row.total_quantity

    data = {
        'item_consumption': item_consumption,
        'machine_consumption': machine_consumption,
        'category_consumption': category_consumption,
        'sub_category_consumption': sub_category_consumption,
        'years': sorted(list(years)),
        'quarters': sorted(list(quarters))
    }
    logger.debug(f"Consumption data: {data}")
    return data

@auth_bp.route('/dashboard/consumption', methods=['GET', 'POST'])
def consumption_dashboard():
    if 'user' not in session:
        flash('Please log in first', 'error')
        return redirect(url_for('auth.login'))

    user_role = session['user']['role']
    user_id = session['user']['id']
    machines = Machine.query.all() if user_role == 'admin' else [Machine.query.get(m['id']) for m in session['user']['machines']]

    if not machines:
        flash('No machines available.', 'error')
        return redirect(url_for('auth.select_machine'))

    # Default filter values
    filters = {
        'year': request.form.get('year') if request.method == 'POST' else None,
        'quarter': request.form.get('quarter') if request.method == 'POST' else None,
        'category': request.form.get('category') if request.method == 'POST' else None,
        'sub_category': request.form.get('sub_category') if request.method == 'POST' else None,
        'machine_id': request.form.get('machine_id') if request.method == 'POST' else None,
        'item_number': request.form.get('item_number') if request.method == 'POST' else None,
        'compare_items': request.form.getlist('compare_items') if request.method == 'POST' else [],
        'compare_machines': request.form.getlist('compare_machines') if request.method == 'POST' else [],
        'compare_categories': request.form.getlist('compare_categories') if request.method == 'POST' else [],
        'compare_sub_categories': request.form.getlist('compare_sub_categories') if request.method == 'POST' else []
    }

    consumption_data = get_quarterly_consumption(
        user_id=user_id,
        role=user_role,
        year=filters['year'],
        quarter=filters['quarter'],
        category=filters['category'],
        sub_category=filters['sub_category'],
        machine_id=filters['machine_id'],
        item_number=filters['item_number']
    )

    # Prepare filter options
    items = Item.query.filter(Item.machine_id.in_([m.id for m in machines])).all()
    item_options = [f"{item.item_number} - {item.name}" for item in items]
    categories = ['Oil and Lubes', 'Spares']
    sub_categories = ['Control Car', 'Camp Car', 'Brake Car', 'Engine Car'] if filters['category'] == 'Spares' else []

    logger.info(f"Rendering consumption dashboard: user={user_id}, filters={filters}")
    return render_template('consumption_dashboard.html',
                         consumption_data=consumption_data,
                         item_options=item_options,
                         machines=machines,
                         categories=categories,
                         sub_categories=sub_categories,
                         user_role=user_role,
                         filters=filters)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            password = request.form.get('password')
            role = request.form.get('role')

            if not username or not password or not role:
                flash('Missing required fields', 'error')
                return redirect(url_for('auth.login'))

            user = User.query.filter_by(username=username, role=role).first()
            if not user or not bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
                flash('Invalid credentials', 'error')
                return redirect(url_for('auth.login'))

            jwt_secret = current_app.config.get('JWT_SECRET')
            if not jwt_secret:
                raise ValueError("JWT_SECRET is not configured")

            token = jwt.encode({
                'user_id': user.id,
                'role': role,
                'exp': datetime.utcnow() + timedelta(hours=1)
            }, jwt_secret, algorithm='HS256')

            machine_list = [{'id': m.id, 'name': m.name} for m in user.machines]
            if role == 'admin':
                machine_list = [{'id': m.id, 'name': m.name} for m in Machine.query.all()]

            session['user'] = {'id': user.id, 'username': username, 'role': role, 'machines': machine_list, 'token': token}
            session.pop('selected_machine', None)
            logger.info(f"Login successful for {username} ({role}) with {len(machine_list)} machines")
            if role == 'admin':
                return redirect(url_for('auth.dashboard'))
            return redirect(url_for('auth.select_machine'))
        except Exception as e:
            flash(f"Login failed: {str(e)}", 'error')
            logger.error(f"Login error: {str(e)}")
            return redirect(url_for('auth.login'))
    return render_template('login.html')

@auth_bp.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            password = request.form.get('password')
            role = request.form.get('role')

            if not username or not password or not role:
                flash('Missing required fields', 'error')
                return redirect(url_for('auth.signup'))

            if role not in ['admin', 'fleet_ops', 'machine_manager']:
                flash('Invalid role', 'error')
                return redirect(url_for('auth.signup'))

            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            user = User(username=username, password=hashed_password, role=role)
            db.session.add(user)
            db.session.commit()
            flash('User created successfully! Please log in.', 'success')
            logger.info(f"Signup successful for {username} ({role})")
            return redirect(url_for('auth.login'))
        except IntegrityError:
            db.session.rollback()
            flash('Username already exists', 'error')
            return redirect(url_for('auth.signup'))
        except Exception as e:
            db.session.rollback()
            flash((f'Signup failed: {str(e)}'), 'error')
            logger.error(f"Signup error: {str(e)}")
            return redirect(url_for('auth.signup'))
    return render_template('signup.html')

@auth_bp.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('auth.login'))

@auth_bp.route('/select-machine', methods=['GET', 'POST'])
def select_machine():
    if 'user' not in session:
        flash('Please log in first', 'error')
        return redirect(url_for('auth.login'))

    machines = session['user']['machines']
    logger.debug(f"User {session['user']['username']} has {len(machines)} machines: {[m['name'] for m in machines]}")

    if not machines:
        flash('No machines available. Contact an admin or initialize machines.', 'error')
        return render_template('select_machine.html', machines=[])

    if request.method == 'POST':
        try:
            machine_id = request.form.get('machine_id')
            if not machine_id:
                flash('Please select a machine', 'error')
                return redirect(url_for('auth.select_machine'))

            machine = next((m for m in machines if str(m['id']) == machine_id), None)
            if not machine:
                flash('Invalid machine selection', 'error')
                return redirect(url_for('auth.select_machine'))

            session['selected_machine'] = {'id': int(machine_id), 'name': machine['name']}
            logger.info(f"User {session['user']['username']} selected machine {machine['name']}")
            return redirect(url_for('auth.dashboard'))
        except Exception as e:
            flash(f'Selection failed: {str(e)}', 'error')
            logger.error(f"Selection error: {str(e)}")
            return redirect(url_for('auth.select_machine'))

    return render_template('select_machine.html', machines=machines)

@auth_bp.route('/admin/manage-access', methods=['GET', 'POST'])
def admin_manage_access():
    if 'user' not in session or session['user']['role'] != 'admin':
        flash('Admin access required', 'error')
        return redirect(url_for('auth.login'))

    users = User.query.filter(User.role.in_(['fleet_ops', 'machine_manager'])).all()
    machines = Machine.query.all()
    logs = AccessLog.query.order_by(AccessLog.timestamp.desc()).limit(50).all()

    if not users:
        flash('No Fleet Ops or Machine Manager users available.', 'error')
    if not machines:
        flash('No machines available. Initialize machines first.', 'error')

    if request.method == 'POST':
        try:
            user_id = request.form.get('user_id')
            machine_ids = request.form.getlist('machine_ids')

            if not user_id:
                flash('Select a user.', 'error')
                return redirect(url_for('auth.admin_manage_access'))

            user = User.query.get(user_id)
            if not user or user.role not in ['fleet_ops', 'machine_manager']:
                flash('Invalid user or role', 'error')
                return redirect(url_for('auth.admin_manage_access'))

            if user.role == 'machine_manager' and len(machine_ids) > 1:
                flash('Machine Manager can have at most one machine', 'error')
                return redirect(url_for('auth.admin_manage_access'))
            elif user.role == 'fleet_ops' and len(machine_ids) > 3:
                flash('Fleet Ops can have at most 3 machines', 'error')
                return redirect(url_for('auth.admin_manage_access'))

            machines_to_assign = Machine.query.filter(Machine.id.in_([int(mid) for mid in machine_ids if mid])).all() if machine_ids else []
            user.machines = machines_to_assign
            db.session.commit()
            flash(f'Machines updated for {user.username}', 'success')
            logger.info(f"Machines assigned to {user.username}: {[m.name for m in machines_to_assign]}")
            return redirect(url_for('auth.admin_manage_access'))
        except Exception as e:
            db.session.rollback()
            flash(f'Assignment failed: {str(e)}', 'error')
            logger.error(f"Assignment error: {str(e)}")
            return redirect(url_for('auth.admin_manage_access'))

    return render_template('admin_manage_access.html', users=users, machines=machines, logs=logs)

@auth_bp.route('/admin/manage-items', methods=['GET', 'POST'])
def admin_manage_items():
    if 'user' not in session or session['user']['role'] != 'admin':
        flash('Admin access required', 'error')
        return redirect(url_for('auth.login'))

    machines = Machine.query.all()
    if not machines:
        flash('No machines available. Initialize machines first.', 'error')
        return redirect(url_for('auth.dashboard'))

    if request.method == 'POST':
        try:
            action = request.form.get('action')
            item_id = request.form.get('item_id')
            item_number = request.form.get('item_number')
            name = request.form.get('name')
            category = request.form.get('category')
            sub_category = request.form.get('sub_category') or None
            quantity = int(request.form.get('quantity'))
            price = float(request.form.get('price'))
            machine_id = int(request.form.get('machine_id'))
            withdraw_quantity = request.form.get('withdraw_quantity')

            if action == 'add':
                if Item.query.filter_by(item_number=item_number).first():
                    flash('Item number already exists', 'error')
                    return redirect(url_for('auth.admin_manage_items'))
                item = Item(
                    item_number=item_number,
                    name=name,
                    category=category,
                    sub_category=sub_category,
                    quantity=quantity,
                    price=price,
                    machine_id=machine_id
                )
                db.session.add(item)
                db.session.commit()
                flash('Item added successfully', 'success')
                logger.info(f"Added item: {item_number}")

            elif action == 'edit':
                item = Item.query.get(item_id)
                if not item:
                    flash('Item not found', 'error')
                    return redirect(url_for('auth.admin_manage_items'))
                if Item.query.filter(Item.item_number == item_number, Item.id != item_id).first():
                    flash('Item number already exists', 'error')
                    return redirect(url_for('auth.admin_manage_items'))
                item.item_number = item_number
                item.name = name
                item.category = category
                item.sub_category = sub_category
                item.quantity = quantity
                item.price = price
                item.machine_id = machine_id
                db.session.commit()
                flash('Item updated successfully', 'success')
                logger.info(f"Updated item: {item_number}")

            elif action == 'withdraw':
                item = Item.query.get(item_id)
                if not item:
                    flash('Item not found', 'error')
                    return redirect(url_for('auth.admin_manage_items'))
                withdraw_qty = int(withdraw_quantity)
                if withdraw_qty <= 0 or withdraw_qty > item.quantity:
                    flash('Invalid withdrawal quantity', 'error')
                    return redirect(url_for('auth.admin_manage_items'))
                item.quantity -= withdraw_qty
                db.session.commit()
                flash(f'Withdrew {withdraw_qty} units of {item_number}', 'success')
                logger.info(f"Withdrew {withdraw_qty} units of {item_number}")

        except ValueError as ve:
            flash(f'Invalid input: {str(ve)}', 'error')
            logger.error(f"Item action error: {str(ve)}")
            return redirect(url_for('auth.admin_manage_items'))
        except Exception as e:
            db.session.rollback()
            flash(f'Action failed: {str(e)}', 'error')
            logger.error(f"Item action error: {str(e)}")
            return redirect(url_for('auth.admin_manage_items'))

    items = Item.query.all()
    categories = ['Oil and Lubes', 'Spares']
    sub_categories = ['Control Car', 'Camp Car', 'Brake Car', 'Engine Car']
    return render_template('admin_manage_items.html', items=items, machines=machines, categories=categories, sub_categories=sub_categories)

@auth_bp.route('/manage-inventory', methods=['GET', 'POST'])
def manage_inventory():
    if 'user' not in session or session['user']['role'] not in ['admin', 'fleet_ops']:
        flash('Access restricted to Admins and Fleet Ops', 'error')
        return redirect(url_for('auth.login'))

    user_role = session['user']['role']
    user_id = session['user']['id']
    machines = Machine.query.all() if user_role == 'admin' else [Machine.query.get(m['id']) for m in session['user']['machines']]

    if not machines:
        flash('No machines available.', 'error')
        return redirect(url_for('auth.select_machine'))

    if request.method == 'POST':
        try:
            if 'file' not in request.files:
                flash('No file uploaded', 'error')
                return redirect(url_for('auth.manage_inventory'))

            file = request.files['file']
            if file.filename == '':
                flash('No file selected', 'error')
                return redirect(url_for('auth.manage_inventory'))

            if file and allowed_file(file.filename, ALLOWED_EXTENSIONS):
                filename = secure_filename(file.filename)
                file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)

                df = pd.read_excel(file_path)
                expected_columns = ['item_number', 'name', 'category', 'sub_category', 'quantity', 'price', 'machine_id']
                if not all(col in df.columns for col in expected_columns):
                    flash('Invalid Excel format. Required columns: ' + ', '.join(expected_columns), 'error')
                    os.remove(file_path)
                    return redirect(url_for('auth.manage_inventory'))

                valid_machines = [m.id for m in machines]
                errors = []
                for index, row in df.iterrows():
                    item_number = str(row['item_number']).strip()
                    name = str(row['name']).strip()
                    category = str(row['category']).strip()
                    sub_category = str(row['sub_category']).strip() if pd.notna(row['sub_category']) else None
                    quantity = int(row['quantity'])
                    price = float(row['price'])
                    machine_id = int(row['machine_id'])

                    if machine_id not in valid_machines:
                        errors.append(f"Row {index+2}: Invalid machine_id {machine_id}")
                        continue

                    if category not in ['Oil and Lubes', 'Spares']:
                        errors.append(f"Row {index+2}: Invalid category {category}")
                        continue

                    if sub_category and sub_category not in ['Control Car', 'Camp Car', 'Brake Car', 'Engine Car']:
                        errors.append(f"Row {index+2}: Invalid sub_category {sub_category}")
                        continue

                    if quantity < 0:
                        errors.append(f"Row {index+2}: Quantity cannot be negative")
                        continue

                    if price < 0:
                        errors.append(f"Row {index+2}: Price cannot be negative")
                        continue

                    if Item.query.filter_by(item_number=item_number).first():
                        errors.append(f"Row {index+2}: Item number {item_number} already exists")
                        continue

                    item = Item(
                        item_number=item_number,
                        name=name,
                        category=category,
                        sub_category=sub_category,
                        quantity=quantity,
                        price=price,
                        machine_id=machine_id
                    )
                    db.session.add(item)
                    logger.info(f"Adding item: {item_number} for machine_id {machine_id}")

                if errors:
                    db.session.rollback()
                    for error in errors:
                        flash(error, 'error')
                    os.remove(file_path)
                    return redirect(url_for('auth.manage_inventory'))

                db.session.commit()
                flash('Inventory added successfully', 'success')
                os.remove(file_path)

                log = AccessLog(user_id=user_id, machine_id=None, action='add_inventory')
                db.session.add(log)
                db.session.commit()
                return redirect(url_for('auth.manage_inventory'))

            else:
                flash('Invalid file type. Only .xlsx or .xls allowed.', 'error')
                return redirect(url_for('auth.manage_inventory'))

        except ValueError as ve:
            db.session.rollback()
            flash(f'Invalid data in file: {str(ve)}', 'error')
            logger.error(f"Excel upload error: {str(ve)}")
            return redirect(url_for('auth.manage_inventory'))
        except Exception as e:
            db.session.rollback()
            flash(f'Upload failed: {str(e)}', 'error')
            logger.error(f"Excel upload error: {str(e)}")
            return redirect(url_for('auth.manage_inventory'))

    return render_template('manage_inventory.html', machines=machines, user_role=user_role)

@auth_bp.route('/inventory', methods=['GET', 'POST'])
def inventory():
    if 'user' not in session:
        flash('Please log in first', 'error')
        return redirect(url_for('auth.login'))

    user_role = session['user']['role']
    user_id = session['user']['id']
    machines = Machine.query.all() if user_role == 'admin' else [Machine.query.get(m['id']) for m in session['user']['machines']]

    if not machines:
        flash('No machines available.', 'error')
        return redirect(url_for('auth.select_machine'))

    machine_id = None
    if user_role == 'admin':
        machine_id = int(request.form.get('machine_id')) if request.method == 'POST' else (session.get('selected_machine', {}).get('id') or machines[0].id)
    else:
        if 'selected_machine' not in session:
            flash('Please select a machine first', 'error')
            return redirect(url_for('auth.select_machine'))
        machine_id = session['selected_machine']['id']

    if user_role != 'admin' and machine_id not in [m.id for m in machines]:
        flash('You are not authorized to access this machine', 'error')
        return redirect(url_for('auth.select_machine'))

    selected_machine = Machine.query.get(machine_id)
    session['selected_machine'] = {'id': selected_machine.id, 'name': selected_machine.name}

    category = request.args.get('category', '')
    sub_category = request.args.get('sub_category', '')
    item_number = request.args.get('item_number', '').strip()

    query = Item.query.filter_by(machine_id=machine_id)
    if category:
        query = query.filter(Item.category == category)
    if sub_category:
        query = query.filter(Item.sub_category == sub_category)
    if item_number:
        query = query.filter(Item.item_number.ilike(f'%{item_number}%'))

    items = query.all()

    categories = ['Oil and Lubes', 'Spares']
    sub_categories = ['Control Car', 'Camp Car', 'Brake Car', 'Engine Car'] if category == 'Spares' else []
    logger.info(f"Inventory: user={session['user']['username']}, machine={selected_machine.name}, category={category}, items={len(items)}")

    log = AccessLog(user_id=user_id, machine_id=machine_id, action='view')
    db.session.add(log)
    db.session.commit()

    return render_template('inventory.html', 
                         items=items, 
                         machines=machines,
                         categories=categories,
                         sub_categories=sub_categories,
                         selected_category=category,
                         selected_sub_category=sub_category,
                         selected_item_number=item_number,
                         selected_machine=selected_machine,
                         user_role=user_role)

@auth_bp.route('/update_inventory', methods=['GET', 'POST'])
def update_inventory():
    if 'user' not in session:
        flash('Please log in first', 'error')
        return redirect(url_for('auth.login'))

    user_role = session['user']['role']
    user_id = session['user']['id']
    machines = Machine.query.all() if user_role == 'admin' else [Machine.query.get(m['id']) for m in session['user']['machines']]

    if not machines:
        flash('No machines available.', 'error')
        return redirect(url_for('auth.select_machine'))

    machine_id = None
    if user_role == 'admin':
        machine_id = int(request.form.get('machine_id')) if request.method == 'POST' and request.form.get('machine_id') else (session.get('selected_machine', {}).get('id') or machines[0].id)
    else:
        if 'selected_machine' not in session:
            flash('Please select a machine', 'error')
            return redirect(url_for('auth.select_machine'))
        machine_id = session['selected_machine']['id']

    if user_role != 'admin' and machine_id not in [m.id for m in machines]:
        flash('You are not authorized to view this machine', 'error')
        return redirect(url_for('auth.select_machine'))

    selected_machine = Machine.query.get(machine_id)
    category = request.args.get('category', '')
    sub_category = request.args.get('sub_category', '')
    item_number = request.args.get('item_number', '').strip()

    query = Item.query.filter_by(machine_id=machine_id)
    if category:
        query = query.filter(Item.category == category)
    if sub_category:
        query = query.filter(Item.sub_category == sub_category)
    if item_number:
        query = query.filter(Item.item_number.ilike(f'%{item_number}%'))

    items = query.all()

    categories = ['Oil and Lubes', 'Spares']
    sub_categories = ['Control Car', 'Camp Car', 'Brake Car', 'Engine Car'] if category == 'Spares' else []
    logger.info(f"Update Inventory: user={session['user']['username']}, machine={selected_machine.name}, category={category}, items={len(items)}")

    if request.method == 'POST' and request.form.get('action') == 'update':
        try:
            item_id = request.form.get('item_id')
            quantity = int(request.form.get('quantity'))

            item = Item.query.get(item_id)
            if not item or item.machine_id != machine_id:
                flash('Invalid item or not found for selected machine', 'error')
                return redirect(url_for('auth.update_inventory'))

            if quantity < 0:
                flash('Quantity cannot be negative', 'error')
                return redirect(url_for('auth.update_inventory'))

            old_quantity = item.quantity
            item.quantity = quantity
            db.session.commit()
            flash(f'Updated quantity for {item.item_number} from {old_quantity} to {quantity}', 'success')
            logger.info(f"User {session['user']['username']} updated item {item.item_number} from {old_quantity} to {quantity}")

            log = AccessLog(user_id=user_id, machine_id=machine_id, action=f'update_quantity_{item.item_number}_from_{old_quantity}_to_{quantity}')
            db.session.add(log)
            db.session.commit()

            return redirect(url_for('auth.update_inventory'))
        except ValueError as ve:
            flash(f'Invalid input: {str(ve)}', 'error')
            logger.error(f"Update inventory error: {str(ve)}")
            return redirect(url_for('auth.update_inventory'))
        except Exception as e:
            db.session.rollback()
            flash(f'Update failed: {str(e)}', 'error')
            logger.error(f"Update inventory error: {str(e)}")
            return redirect(url_for('auth.update_inventory'))

    log = AccessLog(user_id=user_id, machine_id=machine_id, action='view')
    db.session.add(log)
    db.session.commit()

    return render_template('update_inventory.html', 
                         items=items, 
                         machines=machines,
                         categories=categories, 
                         sub_categories=sub_categories,
                         selected_category=category,
                         selected_sub_category=sub_category,
                         selected_item_number=item_number,
                         selected_machine=selected_machine,
                         user_role=user_role)

@auth_bp.route('/withdraw_items', methods=['GET', 'POST'])
def withdraw_items():
    if 'user' not in session:
        flash('Please log in', 'error')
        return redirect(url_for('auth.login'))

    user_role = session['user']['role']
    user_id = session['user']['id']
    machines = Machine.query.all() if user_role == 'admin' else [Machine.query.get(m['id']) for m in session['user']['machines']]

    if not machines:
        flash('No machines available.', 'error')
        return redirect(url_for('auth.select_machine'))

    machine_id = None
    if user_role == 'admin':
        machine_id = int(request.form.get('machine_id')) if request.method == 'POST' and request.form.get('machine_id') else (session.get('selected_machine', {}).get('id') or machines[0].id)
    else:
        if 'selected_machine' not in session:
            flash('Please select a machine first', 'error')
            return redirect(url_for('auth.select_machine'))
        machine_id = session['selected_machine']['id']

    if user_role != 'admin' and machine_id not in [m.id for m in machines]:
        flash('You are not authorized to access this machine', 'error')
        return redirect(url_for('auth.select_machine'))

    selected_machine = Machine.query.get(machine_id)
    session['selected_machine'] = {'id': machine_id, 'name': selected_machine.name}

    category = request.args.get('category', '')
    sub_category = request.args.get('sub_category', '')
    item_number = request.args.get('item_number', '').strip()

    query = Item.query.filter_by(machine_id=machine_id)
    if category:
        query = query.filter(Item.category == category)
    if sub_category:
        query = query.filter(Item.sub_category == sub_category)
    if item_number:
        query = query.filter(Item.item_number.ilike(f'%{item_number}%'))

    items = query.all()

    categories = ['Oil and Lubes', 'Spares']
    sub_categories = ['Control Car', 'Camp Car', 'Brake Car', 'Engine Car'] if category == 'Spares' else []
    logger.info(f"Withdraw Items: user={user_id}, machine={selected_machine.name}, category={category}, items={len(items)}")

    if request.method == 'POST' and request.form.get('action') == 'submit_withdrawal':
        try:
            item_ids = request.form.getlist('item_ids')
            quantities = {key.split('_')[1]: value for key, value in request.form.items() if key.startswith('quantity_')}
            description = request.form.get('description')
            if not item_ids:
                flash('Please select at least one item to withdraw', 'error')
                return redirect(url_for('auth.withdraw_items'))

            if not description:
                flash('Description is required', 'error')
                return redirect(url_for('auth.withdraw_items'))

            photo_path = None
            if 'photo' in request.files:
                photo = request.files['photo']
                if photo.filename and allowed_file(photo.filename, ALLOWED_PHOTO_EXTENSIONS):
                    if photo.content_length > MAX_PHOTO_SIZE:
                        flash('Photo size exceeds 5MB', 'error')
                        return redirect(url_for('auth.withdraw_items'))
                    filename = secure_filename(f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{photo.filename}")
                    photo_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
                    photo.save(photo_path)
                    logger.info(f"Saved photo: {photo_path}")

            errors = []
            withdrawal_ids = []
            for item_id in item_ids:
                item = Item.query.get(item_id)
                if not item or item.machine_id != machine_id:
                    errors.append(f"Item {item_id} not found or not associated with selected machine")
                    continue

                qty_key = str(item_id)
                if qty_key not in quantities or not quantities[qty_key]:
                    errors.append(f"Quantity not provided for item {item.item_number}")
                    continue

                withdraw_qty = int(quantities[qty_key])
                if withdraw_qty <= 0 or withdraw_qty > item.quantity:
                    errors.append(f"Invalid withdrawal quantity for {item.item_number}")
                    continue

                withdrawal = Withdrawal(
                    item_id=item_id,
                    quantity=withdraw_qty,
                    description=description,
                    photo_path=photo_path,
                    user_id=user_id,
                    machine_id=machine_id,
                    status='pending'
                )
                db.session.add(withdrawal)
                db.session.flush()
                withdrawal_ids.append(withdrawal.id)
                logger.info(f"Created pending withdrawal for {item.item_number}: {withdraw_qty} units")

            if errors:
                db.session.rollback()
                for error in errors:
                    flash(error, 'error')
                if photo_path and os.path.exists(photo_path):
                    os.remove(photo_path)
                return redirect(url_for('auth.withdraw_items'))

            db.session.commit()
            flash('Withdrawal request submitted, pending approval', 'success')

            log = AccessLog(user_id=user_id, machine_id=machine_id, action='submit_withdrawal')
            db.session.add(log)
            db.session.commit()

            session['withdrawal_ids'] = withdrawal_ids
            logger.info(f"Redirecting to select-receipt-format with withdrawal_ids: {withdrawal_ids}")
            return redirect(url_for('auth.select_receipt_format'))

        except ValueError as ve:
            db.session.rollback()
            if photo_path and os.path.exists(photo_path):
                os.remove(photo_path)
            flash(f'Invalid input: {str(ve)}', 'error')
            logger.error(f"Withdraw error: {str(ve)}")
            return redirect(url_for('auth.withdraw_items'))
        except Exception as e:
            db.session.rollback()
            if photo_path and os.path.exists(photo_path):
                os.remove(photo_path)
            flash(f'Withdrawal failed: {str(e)}', 'error')
            logger.error(f"Withdraw error: {str(e)}")
            return redirect(url_for('auth.withdraw_items'))

    log = AccessLog(user_id=user_id, machine_id=machine_id, action='view')
    db.session.add(log)
    db.session.commit()

    return render_template('withdraw_items.html', 
                         items=items, 
                         machines=machines,
                         categories=categories,
                         sub_categories=sub_categories,
                         selected_category=category,
                         selected_sub_category=sub_category,
                         selected_item_number=item_number,
                         selected_machine=selected_machine,
                         user_role=user_role)
    
@auth_bp.route('/notifications', methods=['GET'])
def notifications():
    if 'user' not in session:
        flash('Please log in', 'error')
        return redirect(url_for('auth.login'))

    user_role = session['user']['role']
    machine_id = request.args.get('machine_id') or session.get('selected_machine', {}).get('id')

    query = Notification.query.join(Item)
    if user_role != 'admin' and machine_id:
        query = query.filter(Item.machine_id == machine_id)
    notifications = query.order_by(Notification.timestamp.desc()).all()

    machines = Machine.query.all() if user_role == 'admin' else [Machine.query.get(m['id']) for m in session['user']['machines']]
    return render_template('notifications.html', notifications=notifications, machines=machines, user_role=user_role, selected_machine_id=machine_id if machine_id else None)

@auth_bp.route('/select_receipt_format', methods=['GET', 'POST'])
def select_receipt_format():
    if 'user' not in session or 'withdrawal_ids' not in session:
        flash('Invalid access or session expired', 'error')
        logger.warning("Invalid access to select_receipt_format")
        return redirect(url_for('auth.withdraw_items'))

    if request.method == 'POST':
        try:
            format_type = request.form.get('format')
            if format_type not in ['loram', 'general']:
                flash('Invalid receipt format', 'error')
                return redirect(url_for('auth.select_receipt_format'))

            withdrawals = Withdrawal.query.filter(Withdrawal.id.in_(session['withdrawal_ids'])).all()
            if not withdrawals:
                flash('No withdrawal data found', 'error')
                session.pop('withdrawal_ids', None)
                return redirect(url_for('auth.withdraw_items'))

            buffer = BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=letter)
            styles = getSampleStyleSheet()
            elements = []

            if format_type == 'loram':
                elements.append(Paragraph("Loram Maintenance of Way, Inc.", styles['Title']))
                elements.append(Paragraph("Inventory Withdrawal Receipt", styles['Heading2']))
                elements.append(Spacer(1, 12))
                elements.append(Paragraph(f"Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
                elements.append(Paragraph(f"User: {session['user']['username']}", styles['Normal']))
                elements.append(Paragraph(f"Machine: {withdrawals[0].machine.name}", styles['Normal']))
                elements.append(Spacer(1, 12))

                data = [['Item Number', 'Name', 'Quantity', 'Description']]
                for w in withdrawals:
                    data.append([w.item.item_number, w.item.name, w.quantity, w.description])
                
                table = Table(data)
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 14),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                elements.append(table)

            else:  # general
                elements.append(Paragraph("General Withdrawal Receipt", styles['Heading1']))
                elements.append(Spacer(1, 12))
                elements.append(Paragraph(f"Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
                elements.append(Paragraph(f"User: {session['user']['username']}", styles['Normal']))
                elements.append(Paragraph(f"Machine: {withdrawals[0].machine.name}", styles['Normal']))
                elements.append(Spacer(1, 12))

                for w in withdrawals:
                    elements.append(Paragraph(f"Item: {w.item.item_number} - {w.item.name}", styles['Normal']))
                    elements.append(Paragraph(f"Quantity: {w.quantity}", styles['Normal']))
                    elements.append(Paragraph(f"Description: {w.description}", styles['Normal']))
                    elements.append(Spacer(1, 6))

            doc.build(elements)
            buffer.seek(0)
            session.pop('withdrawal_ids', None)
            logger.info(f"Generated {format_type} receipt for user {session['user']['username']}")
            return send_file(buffer, download_name=f"withdrawal_receipt_{format_type}.pdf", as_attachment=True)

        except Exception as e:
            flash(f'Receipt generation failed: {str(e)}', 'error')
            logger.error(f"Receipt generation error: {str(e)}")
            return redirect(url_for('auth.select_receipt_format'))

    return render_template('select_receipt_format.html')

@auth_bp.route('/pending-withdrawals', methods=['GET', 'POST'])
def pending_withdrawals():
    if 'user' not in session or session['user']['role'] not in ['admin', 'machine_manager']:
        flash('Unauthorized access', 'error')
        return redirect(url_for('auth.login'))

    user_id = session['user']['id']
    user_role = session['user']['role']
    machine_id = request.args.get('machine_id') or session.get('selected_machine', {}).get('id')

    if not machine_id:
        flash('Please select a machine', 'error')
        return redirect(url_for('auth.select_machine'))

    machine_id = int(machine_id)
    valid_machine_ids = [m.id for m in Machine.query.all()] if user_role == 'admin' else [m['id'] for m in session['user']['machines']]
    if machine_id not in valid_machine_ids:
        flash('Unauthorized access to this machine', 'error')
        return redirect(url_for('auth.select_machine'))

    query = Withdrawal.query.filter_by(machine_id=machine_id, status='pending')
    withdrawals = query.order_by(Withdrawal.timestamp.desc()).all()
    logger.info(f"Pending withdrawals: user={user_id}, machines={valid_machine_ids}, selected_machine={machine_id}, count={len(withdrawals)}")

    if request.method == 'POST' and 'action' in request.form:
        try:
            action = request.form.get('action')
            withdrawal_id = request.form.get('withdrawal_id')
            withdrawal = Withdrawal.query.get(withdrawal_id)
            
            if not withdrawal or withdrawal.machine_id not in valid_machine_ids:
                flash('Invalid withdrawal or unauthorized access', 'error')
                return redirect(url_for('auth.pending_withdrawals'))

            if action == 'approve':
                if withdrawal.status != 'pending':
                    flash('Withdrawal already processed', 'error')
                    return redirect(url_for('auth.pending_withdrawals'))
                
                item = Item.query.get(withdrawal.item_id)
                if withdrawal.quantity > item.quantity:
                    flash(f'Insufficient quantity for {item.item_number}', 'error')
                    return redirect(url_for('auth.pending_withdrawals'))

                old_status = item.get_status()  # Get status before update
                item.quantity -= withdrawal.quantity
                withdrawal.status = 'approved'
                new_status = item.get_status()  # Get status after update
                db.session.commit()
                create_notification(item, old_status, new_status)  # Create notification
                flash(f'Withdrawal approved for {item.item_number}', 'success')
                logger.info(f"Approved withdrawal {withdrawal_id} for {item.item_number}")

            elif action == 'reject':
                if withdrawal.status != 'pending':
                    flash('Withdrawal already processed', 'error')
                    return redirect(url_for('auth.pending_withdrawals'))
                
                if withdrawal.photo_path and os.path.exists(withdrawal.photo_path):
                    os.remove(withdrawal.photo_path)
                withdrawal.status = 'rejected'
                db.session.commit()
                flash(f'Withdrawal rejected for {item.item_number}', 'success')
                logger.info(f"Rejected withdrawal {withdrawal_id} for {item.item_number}")

            log = AccessLog(user_id=user_id, machine_id=withdrawal.machine_id, action=f'{action}_withdrawal')
            db.session.add(log)
            db.session.commit()

            return redirect(url_for('auth.pending_withdrawals'))

        except Exception as e:
            db.session.rollback()
            flash(f'Action failed: {str(e)}', 'error')
            logger.error(f"Pending withdrawal error: {str(e)}")
            return redirect(url_for('auth.pending_withdrawals'))

    machines = Machine.query.all() if user_role == 'admin' else [Machine.query.get(m['id']) for m in session['user']['machines']]
    return render_template('pending_withdrawals.html', withdrawals=withdrawals, machines=machines, user_role=user_role, selected_machine_id=machine_id)

@auth_bp.route('/dashboard')
def dashboard():
    if 'user' not in session:
        flash('Please log in first', 'error')
        return redirect(url_for('auth.login'))

    if session['user']['role'] != 'admin' and 'selected_machine' not in session:
        return redirect(url_for('auth.select_machine'))

    if session['user']['role'] == 'admin':
        all_machines = Machine.query.all()
        session['user']['machines'] = [{'id': m.id, 'name': m.name} for m in all_machines]

    return render_template('dashboard.html', user=session['user'], selected_machine=session.get('selected_machine'))



@auth_bp.route('/init-machines', methods=['GET'])
def init_machines_route():
    try:
        logger.info("Checking database tables...")
        inspector = inspect(db.engine)
        if not inspector.has_table('machines'):
            logger.info("No machines table found. Creating tables...")
            db.create_all()
        
        init_machines()
        init_sample_items()
        machines = Machine.query.all()
        items = Item.query.all()
        if not machines:
            raise ValueError("No machines initialized")
        logger.info(f"Initialized {len(machines)} machines and {len(items)} items")
        return jsonify({
            'message': 'Successfully initialized machines',
            'machines': [m.name for m in machines],
            'items': [i.item_number for i in items]
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error: {str(e)}")
        return jsonify({'error': str(e)})

def init_sample_items():
    logger.info("Initializing sample items...")
    sample_items = [
        {'item_number': 'ITEM-001', 'name': 'Engine Oil', 'category': 'Oil and Lubes', 'sub_category': None, 'quantity': 100, 'price': 50.0, 'machine_id': 1},
        {'item_number': 'ITEM-002', 'name': 'Lubricant', 'category': 'Oil and Lubes', 'sub_category': None, 'quantity': 50, 'price': 30.0, 'machine_id': 1},
        {'item_number': 'ITEM-003', 'name': 'Control Car Gear', 'category': 'Spares', 'sub_category': 'Control Car', 'quantity': 20, 'price': 200.0, 'machine_id': 1},
        {'item_number': 'ITEM-004', 'name': 'Engine Car Valve', 'category': 'Spares', 'sub_category': 'Engine Car', 'quantity': 10, 'price': 500.0, 'machine_id': 1},
        {'item_number': 'ITEM-005', 'name': 'Hydraulic Oil', 'category': 'Oil and Lubes', 'sub_category': None, 'quantity': 80, 'price': 45.0, 'machine_id': 2},
        {'item_number': 'ITEM-006', 'name': 'Grease', 'category': 'Oil and Lubes', 'sub_category': None, 'quantity': 60, 'price': 25.0, 'machine_id': 2},
        {'item_number': 'ITEM-007', 'name': 'Camp Car Wheel', 'category': 'Spares', 'sub_category': 'Camp Car', 'quantity': 15, 'price': 150.0, 'machine_id': 2},
        {'item_number': 'ITEM-008', 'name': 'Brake Car Pad', 'category': 'Spares', 'sub_category': 'Brake Car', 'quantity': 30, 'price': 100.0, 'machine_id': 2},
        {'item_number': 'ITEM-009', 'name': 'Transmission Oil', 'category': 'Oil and Lubes', 'sub_category': None, 'quantity': 90, 'price': 55.0, 'machine_id': 3},
        {'item_number': 'ITEM-010', 'name': 'Coolant', 'category': 'Oil and Lubes', 'sub_category': None, 'quantity': 40, 'price': 35.0, 'machine_id': 3},
        {'item_number': 'ITEM-011', 'name': 'Control Car Sensor', 'category': 'Spares', 'sub_category': 'Control Car', 'quantity': 25, 'price': 180.0, 'machine_id': 3},
        {'item_number': 'ITEM-012', 'name': 'Engine Car Piston', 'category': 'Spares', 'sub_category': 'Engine Car', 'quantity': 12, 'price': 220.0, 'machine_id': 3},
        {'item_number': 'ITEM-013', 'name': 'Brake Fluid', 'category': 'Oil and Lubes', 'sub_category': None, 'quantity': 70, 'price': 40.0, 'machine_id': 4},
        {'item_number': 'ITEM-014', 'name': 'Synthetic Oil', 'category': 'Oil and Lubes', 'sub_category': None, 'quantity': 55, 'price': 60.0, 'machine_id': 4},
        {'item_number': 'ITEM-015', 'name': 'Camp Car Axle', 'category': 'Spares', 'sub_category': 'Camp Car', 'quantity': 18, 'price': 170.0, 'machine_id': 4},
        {'item_number': 'ITEM-016', 'name': 'Brake Car Disc', 'category': 'Spares', 'sub_category': 'Brake Car', 'quantity': 28, 'price': 110.0, 'machine_id': 4},
        {'item_number': 'ITEM-017', 'name': 'Gear Oil', 'category': 'Oil and Lubes', 'sub_category': None, 'quantity': 85, 'price': 48.0, 'machine_id': 5},
        {'item_number': 'ITEM-018', 'name': 'Motor Oil', 'category': 'Oil and Lubes', 'sub_category': None, 'quantity': 65, 'price': 38.0, 'machine_id': 5},
        {'item_number': 'ITEM-019', 'name': 'Control Car Module', 'category': 'Spares', 'sub_category': 'Control Car', 'quantity': 22, 'price': 190.0, 'machine_id': 5},
        {'item_number': 'ITEM-020', 'name': 'Engine Car Injector', 'category': 'Spares', 'sub_category': 'Engine Car', 'quantity': 14, 'price': 230.0, 'machine_id': 5},
        {'item_number': 'ITEM-021', 'name': 'Differential Oil', 'category': 'Oil and Lubes', 'sub_category': None, 'quantity': 75, 'price': 52.0, 'machine_id': 6},
        {'item_number': 'ITEM-022', 'name': 'Power Steering Fluid', 'category': 'Oil and Lubes', 'sub_category': None, 'quantity': 45, 'price': 32.0, 'machine_id': 6},
        {'item_number': 'ITEM-023', 'name': 'Camp Car Suspension', 'category': 'Spares', 'sub_category': 'Camp Car', 'quantity': 16, 'price': 160.0, 'machine_id': 6},
        {'item_number': 'ITEM-024', 'name': 'Brake Car Caliper', 'category': 'Spares', 'sub_category': 'Brake Car', 'quantity': 26, 'price': 120.0, 'machine_id': 6},
        {'item_number': 'ITEM-025', 'name': 'Compressor Oil', 'category': 'Oil and Lubes', 'sub_category': None, 'quantity': 95, 'price': 58.0, 'machine_id': 7},
        {'item_number': 'ITEM-026', 'name': 'Antifreeze', 'category': 'Oil and Lubes', 'sub_category': None, 'quantity': 50, 'price': 28.0, 'machine_id': 7},
        {'item_number': 'ITEM-027', 'name': 'Control Car Relay', 'category': 'Spares', 'sub_category': 'Control Car', 'quantity': 24, 'price': 175.0, 'machine_id': 7},
        {'item_number': 'ITEM-028', 'name': 'Engine Car Belt', 'category': 'Spares', 'sub_category': 'Engine Car', 'quantity': 13, 'price': 210.0, 'machine_id': 7},
        {'item_number': 'ITEM-029', 'name': 'Turbine Oil', 'category': 'Oil and Lubes', 'sub_category': None, 'quantity': 88, 'price': 47.0, 'machine_id': 8},
        {'item_number': 'ITEM-030', 'name': 'Silicone Lubricant', 'category': 'Oil and Lubes', 'sub_category': None, 'quantity': 62, 'price': 33.0, 'machine_id': 8},
        {'item_number': 'ITEM-031', 'name': 'Camp Car Frame', 'category': 'Spares', 'sub_category': 'Camp Car', 'quantity': 19, 'price': 165.0, 'machine_id': 8},
        {'item_number': 'ITEM-032', 'name': 'Brake Car Rotor', 'category': 'Spares', 'sub_category': 'Brake Car', 'quantity': 27, 'price': 115.0, 'machine_id': 8},
        {'item_number': 'ITEM-033', 'name': 'Synthetic Grease', 'category': 'Oil and Lubes', 'sub_category': None, 'quantity': 82, 'price': 44.0, 'machine_id': 9},
        {'item_number': 'ITEM-034', 'name': 'Cooling Fluid', 'category': 'Oil and Lubes', 'sub_category': None, 'quantity': 48, 'price': 36.0, 'machine_id': 9},
        {'item_number': 'ITEM-035', 'name': 'Control Car Actuator', 'category': 'Spares', 'sub_category': 'Control Car', 'quantity': 23, 'price': 185.0, 'machine_id': 9},
        {'item_number': 'ITEM-036', 'name': 'Engine Car Gasket', 'category': 'Spares', 'sub_category': 'Engine Car', 'quantity': 11, 'price': 240.0, 'machine_id': 9},
        {'item_number': 'ITEM-037', 'name': 'Chain Oil', 'category': 'Oil and Lubes', 'sub_category': None, 'quantity': 78, 'price': 49.0, 'machine_id': 10},
        {'item_number': 'ITEM-038', 'name': 'Bearing Grease', 'category': 'Oil and Lubes', 'sub_category': None, 'quantity': 50, 'price': 31.0, 'machine_id': 10},
        {'item_number': 'ITEM-039', 'name': 'Camp Car Shock', 'category': 'Spares', 'sub_category': 'Camp Car', 'quantity': 17, 'price': 155.0, 'machine_id': 10},
        {'item_number': 'ITEM-040', 'name': 'Brake Car Drum', 'category': 'Spares', 'sub_category': 'Brake Car', 'quantity': 29, 'price': 105.0, 'machine_id': 10}
    ]

    count_added = 0
    for item_data in sample_items:
        if not Item.query.filter_by(item_number=item_data['item_number']).first():
            try:
                item = Item(**item_data)
                db.session.add(item)
                db.session.flush()
                logger.info(f"Added item: {item_data['item_number']}")
                count_added += 1
            except Exception as e:
                logger.error(f"Error adding item {item_data['item_number']}: {str(e)}")
        else:
            logger.debug(f"Item {item_data['item_number']} already exists")

    try:
        db.session.commit()
        logger.info(f"Sample items initialized: {count_added} items added")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Sample items initialization failed: {str(e)}")
        raise e