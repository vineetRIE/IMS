from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

user_machines = db.Table('user_machines',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('machine_id', db.Integer, db.ForeignKey('machine.id'), primary_key=True)
)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # admin, fleet_ops, machine_manager
    machines = db.relationship('Machine', secondary=user_machines, backref=db.backref('users', lazy=True))

class Machine(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    items = db.relationship('Item', backref='machine', lazy=True)

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    machine_id = db.Column(db.Integer, db.ForeignKey('machine.id'), nullable=False)
    item_number = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=0)
    category = db.Column(db.String(50), nullable=True)
    sub_category = db.Column(db.String(50), nullable=True)
    price = db.Column(db.Integer, nullable=True)
    mmf = db.Column(db.Integer, nullable=False, default=0)  # Minimum Monthly Forecast

    def get_status(self):
        if self.quantity == 0:
            return 'red'
        elif self.quantity < 3 * self.mmf:
            return 'yellow'
        else:
            return 'green'

class AccessLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='access_logs')  # Added relationship
    machine_id = db.Column(db.Integer, db.ForeignKey('machine.id'), nullable=False)
    machine = db.relationship('Machine', backref='access_logs')  # Added relationship
    action = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Withdrawal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey('item.id'), nullable=False)
    item = db.relationship('Item', backref='withdrawals')
    quantity = db.Column(db.Integer, nullable=False)
    description = db.Column(db.String(200))
    photo_path = db.Column(db.String(200))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='withdrawals')  # Added relationship
    machine_id = db.Column(db.Integer, db.ForeignKey('machine.id'), nullable=False)
    machine = db.relationship('Machine', backref='withdrawals')
    status = db.Column(db.String(20), nullable=False, default='pending')  # pending, approved, rejected
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    class PurchaseOrder(db.Model):
     id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey('item.id'), nullable=False)
    item = db.relationship('Item', backref='purchase_orders')
    quantity = db.Column(db.Integer, nullable=False)
    description = db.Column(db.String(200))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='purchase_orders')
    machine_id = db.Column(db.Integer, db.ForeignKey('machine.id'), nullable=False)
    machine = db.relationship('Machine', backref='purchase_orders')
    status = db.Column(db.String(20), nullable=False, default='pending')  # pending, approved, rejected
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey('item.id'), nullable=False)
    item = db.relationship('Item', backref='notifications')
    old_status = db.Column(db.String(20), nullable=False)  # red, yellow, green
    new_status = db.Column(db.String(20), nullable=False)
    message = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)