from flask import Flask, redirect, url_for, jsonify
from routes.auth import auth_bp
import os
from models.user import db
from datetime import datetime
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///inventory.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'static/uploads')
app.config['JWT_SECRET'] = os.environ.get('JWT_SECRET_KEY', 'your-jwt-secret-key')

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db.init_app(app)

app.register_blueprint(auth_bp)

def basename(path):
    return os.path.basename(path) if path else ''

app.jinja_env.filters['basename'] = basename

@app.route('/')
def index():
    return redirect(url_for('auth.login'))

@app.route('/seed-data', methods=['GET'])
def seed_data():
    from models.user import User, Machine, Item, Withdrawal
    try:
        with app.app_context():
            if not Machine.query.count() or not User.query.count():
                return jsonify({'error': 'Initialize machines and users first'}), 400

            sample_withdrawals = [
                {'item_id': 1, 'quantity': 5, 'machine_id': 1, 'user_id': 2, 'description': 'Engine maintenance Q1 2025', 'status': 'approved', 'timestamp': datetime(2025, 1, 15)},
                {'item_id': 3, 'quantity': 2, 'machine_id': 1, 'user_id': 2, 'description': 'Gear replacement Q2 2025', 'status': 'approved', 'timestamp': datetime(2025, 4, 10)},
                {'item_id': 1, 'quantity': 8, 'machine_id': 1, 'user_id': 2, 'description': 'Oil top-up Q3 2025', 'status': 'approved', 'timestamp': datetime(2025, 7, 20)},
                {'item_id': 4, 'quantity': 3, 'machine_id': 1, 'user_id': 2, 'description': 'Valve replacement Q4 2025', 'status': 'approved', 'timestamp': datetime(2025, 10, 5)},
                {'item_id': 7, 'quantity': 4, 'machine_id': 2, 'user_id': 2, 'description': 'Wheel maintenance Q1 2025', 'status': 'approved', 'timestamp': datetime(2025, 1, 20)},
                {'item_id': 8, 'quantity': 6, 'machine_id': 2, 'user_id': 2, 'description': 'Brake pad replacement Q2 2025', 'status': 'approved', 'timestamp': datetime(2025, 4, 15)},
            ]

            item_updates = [
                {'id': 1, 'mmf': 10},  # ITEM-001
                {'id': 3, 'mmf': 5},   # ITEM-003
                {'id': 4, 'mmf': 5},   # ITEM-004
                {'id': 7, 'mmf': 5},   # ITEM-007
                {'id': 8, 'mmf': 5},   # ITEM-008
            ]

            for update in item_updates:
                item = Item.query.get(update['id'])
                if item:
                    item.mmf = update['mmf']

            for data in sample_withdrawals:
                if not Withdrawal.query.filter_by(description=data['description']).first():
                    withdrawal = Withdrawal(**data)
                    db.session.add(withdrawal)
                    item = Item.query.get(data['item_id'])
                    if item and item.quantity >= data['quantity']:
                        item.quantity -= data['quantity']
                    else:
                        db.session.rollback()
                        return jsonify({'error': f'Insufficient quantity for {item.item_number}'}), 400

            db.session.commit()
            return jsonify({'success': 'Sample withdrawals and MMF seeded'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)