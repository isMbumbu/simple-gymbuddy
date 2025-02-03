from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_marshmallow import Marshmallow
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, JWTManager
from flask_jwt_extended import jwt_required, decode_token, JWTManager
from jwt.exceptions import ExpiredSignatureError, DecodeError
import bcrypt
from dotenv import load_dotenv
from datetime import timedelta
from datetime import datetime
import os
from flask import jsonify, request
from flask import render_template, request, jsonify
from flask_cors import CORS
from datetime import datetime
import asyncio


# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

CORS(app)

# Database Configuration
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
    "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT")
}

# Setup Flask config for SQLAlchemy and JWT
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL")
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")  # Change this for production!
jwt = JWTManager(app)

# Initialize DB and other utilities
db = SQLAlchemy(app)
migrate = Migrate(app, db)  # Initialize migrations
mallow = Marshmallow(app)

# Tables
class Role(db.Model):
    __tablename__ = "role"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    members = db.relationship('Member', back_populates="role")

class Member(db.Model):
    __tablename__ = "member"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(250), nullable=False, unique=True)
    password = db.Column(db.String(500), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id', ondelete='CASCADE'), nullable=False)
    role = db.relationship("Role", back_populates="members")

class WorkoutPlan(db.Model):
    __tablename__ = "workout_plan"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(500), nullable=False)
    trainer_id = db.Column(db.Integer, db.ForeignKey('member.id', ondelete='CASCADE'), nullable=False)
    trainer = db.relationship("Member", backref="workout_plans")
    members = db.relationship('Member', secondary='member_workout', back_populates="workout_plans")

class MemberWorkout(db.Model):
    __tablename__ = 'member_workout'
    member_id = db.Column(db.Integer, db.ForeignKey('member.id', ondelete='CASCADE'), primary_key=True)
    workout_plan_id = db.Column(db.Integer, db.ForeignKey('workout_plan.id', ondelete='CASCADE'), primary_key=True)

class Class(db.Model):
    __tablename__ = "class"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(500), nullable=False)
    trainer_id = db.Column(db.Integer, db.ForeignKey('member.id', ondelete='CASCADE'), nullable=False)
    trainer = db.relationship("Member", backref="classes")
    members = db.relationship('Member', secondary='member_class', back_populates="classes")

class MemberClass(db.Model):
    __tablename__ = 'member_class'
    member_id = db.Column(db.Integer, db.ForeignKey('member.id', ondelete='CASCADE'), primary_key=True)
    class_id = db.Column(db.Integer, db.ForeignKey('class.id', ondelete='CASCADE'), primary_key=True)

class ProgressLog(db.Model):
    __tablename__ = "progress_log"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    member_id = db.Column(db.Integer, db.ForeignKey('member.id', ondelete='CASCADE'), nullable=False)
    weight = db.Column(db.Float)
    reps = db.Column(db.Integer)
    sets = db.Column(db.Integer)
    date = db.Column(db.DateTime, nullable=False)

    member = db.relationship("Member", backref="progress_logs")

# Schemas
class RoleSchema(mallow.SQLAlchemyAutoSchema):
    class Meta:
        model = Role
        include_relationships = True
        load_instance = True
    members = mallow.auto_field()

class MemberSchema(mallow.SQLAlchemyAutoSchema):
    class Meta:
        model = Member
        include_fk = True
        load_instance = True
    role = mallow.auto_field()

class WorkoutPlanSchema(mallow.SQLAlchemyAutoSchema):
    class Meta:
        model = WorkoutPlan
        include_fk = True
        load_instance = True
    trainer = mallow.auto_field()

class ClassSchema(mallow.SQLAlchemyAutoSchema):
    class Meta:
        model = Class
        include_fk = True
        load_instance = True
    trainer = mallow.auto_field()

class ProgressLogSchema(mallow.SQLAlchemyAutoSchema):
    class Meta:
        model = ProgressLog
        include_fk = True
        load_instance = True
    member = mallow.auto_field()

class Booking(db.Model):
    __tablename__ = "booking"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    class_id = db.Column(db.Integer, db.ForeignKey('class.id', ondelete='CASCADE'), nullable=False)
    trainer_id = db.Column(db.Integer, db.ForeignKey('member.id', ondelete='CASCADE'), nullable=False)
    member_id = db.Column(db.Integer, db.ForeignKey('member.id', ondelete='CASCADE'), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    class_ = db.relationship("Class", backref="bookings")
    trainer = db.relationship("Member", foreign_keys=[trainer_id])
    member = db.relationship("Member", foreign_keys=[member_id])


# Initialize Schemas
role_schema = RoleSchema()
roles_schema = RoleSchema(many=True)
member_schema = MemberSchema()
members_schema = MemberSchema(many=True)
workout_plan_schema = WorkoutPlanSchema()
workout_plans_schema = WorkoutPlanSchema(many=True)
class_schema = ClassSchema()
classes_schema = ClassSchema(many=True)
progress_log_schema = ProgressLogSchema()
progress_logs_schema = ProgressLogSchema(many=True)

# Routes



@app.route("/sign-up", methods=["POST"])
def signup():
    if request.content_type != 'application/json':
        return jsonify({"message": "Content-type must be application/json"}), 415

    data = request.get_json()
    if not data:
        return jsonify({"message": "Invalid JSON data"}), 400

    # Check for required fields
    if not data.get('name') or not data.get('email') or not data.get('password'):
        return jsonify({"message": "Missing required fields"}), 400

    # Check if email is already in use
    existing_member = Member.query.filter_by(email=data.get('email')).first()
    if existing_member:
        return jsonify({"message": "Email already in use"}), 400

    name = data.get('name')
    email = data.get('email')
    password = data.get('password')

    # Default role (e.g., "user") if role_id is not provided
    role_id = data.get('role_id') or Role.query.filter_by(name='user').first().id
    if not role_id:
        return jsonify({"message": "Invalid or missing role_id"}), 400

    # Hash the password
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

    # Add new member
    new_member = Member(name=name, email=email, role_id=role_id, password=hashed_password)
    db.session.add(new_member)
    db.session.commit()

    return jsonify({"message": "Sign up successful", "member": member_schema.dump(new_member)})


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    member = Member.query.filter_by(email=email).first()
    if not member or not bcrypt.checkpw(password.encode('utf-8'), member.password.encode('utf-8')):
        return jsonify({"message": "Invalid credentials"}), 400

    # Mask the password
    member.password = "########"
    
    # Create an access token
    access_token = create_access_token(identity=str(member.id), expires_delta=timedelta(days=1))

    # Extract role name as a string
    role_name = member.role.name if member.role else "user"  # Handle the case if the role is None

    return jsonify({
    "message": f"Welcome {member.name}",
    "access_token": access_token,
    "role": role_name,  # Role as a string
    "member_id": member.id,
    "trainer_id": member.trainer_id if member.role.name == "trainer" else None,  # Only for trainers
    "admin_id": member.admin_id if member.role.name == "admin" else None  # Only for admins
})


 

@app.route('/workout-plan', methods=["POST"])
@jwt_required()  # Ensure the user is logged in (JWT token required)
def create_workout_plan():
    trainer_id = get_jwt_identity()  # Get trainer's ID from the JWT token

    data = request.get_json()

    app.logger.debug(f"Received data: {data}")  # Log the incoming request data

    # Ensure the name and description are provided
    name = data.get("name")
    description = data.get("description")

    if not name or not description:
        return jsonify({"message": "Name and description are required."}), 400

    new_workout_plan = WorkoutPlan(
        name=name,
        description=description,
        trainer_id=trainer_id
    )

    try:
        db.session.add(new_workout_plan)
        db.session.commit()
        return jsonify({"message": "Workout plan created successfully.", "id": new_workout_plan.id}), 201

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error creating workout plan: {e}")
        return jsonify({"message": "An error occurred while creating the workout plan.", "error": str(e)}), 500


@app.route("/assign-workout-plan", methods=["POST"])
@jwt_required()
def assign_workout_plan():
    data = request.get_json()
    member_id = data.get("member_id")
    workout_plan_id = data.get("workout_plan_id")

    member = Member.query.get(member_id)
    workout_plan = WorkoutPlan.query.get(workout_plan_id)

    if not member_id or not workout_plan_id:
        return jsonify({"error": "Missing member_id or workout_plan_id"}), 422


    member.workout_plans.append(workout_plan)
    db.session.commit()

    return jsonify({"message": "Workout Plan assigned to member successfully"})

@app.route("/class", methods=["POST"])
@jwt_required()
def create_class():
    data = request.get_json()
    
    # Extract fields from the request
    name = data.get('name')
    description = data.get('description')
    
    # Get the trainer_id from JWT token
    trainer_id = get_jwt_identity()

    # Validate input
    if not name or not description:
        return jsonify({"message": "Missing required fields"}), 400

    # Ensure the user is a trainer
    trainer = Member.query.get(trainer_id)
    if trainer is None or trainer.role.name.lower() != 'trainer':
        return jsonify({"message": "Only trainers can create classes"}), 403

    # Create new class
    new_class = Class(
        name=name,
        description=description,
        trainer_id=trainer_id
    )

    # Add to the database
    db.session.add(new_class)
    db.session.commit()

    # Return success message with the new class data
    return jsonify({"message": "Class created", "class": class_schema.dump(new_class)}), 201


@app.route("/class", methods=["GET"])
@jwt_required()
def get_classes():
    user_id = get_jwt_identity()
    app.logger.debug(f"User ID from JWT: {user_id}")

    if not user_id:
        return jsonify({"message": "User ID not found in token"}), 400

    # Retrieve the user
    user = Member.query.get(user_id)
    if not user:
        return jsonify({"message": "User not found"}), 404

    # Fetch all classes (Previously filtered only by trainer ID)
    all_classes = Class.query.all()

    if not all_classes:
        return jsonify({"message": "No classes found"}), 404

    return jsonify({"classes": classes_schema.dump(all_classes)}), 200


@app.route("/log-progress", methods=["POST"])
@jwt_required()
def log_progress():
    data = request.get_json()
    
    weight = data.get('weight')
    reps = data.get('reps')
    sets = data.get('sets')
    member_id = get_jwt_identity()

    # Validate progress input
    if not weight or not reps or not sets:
        return jsonify({"message": "Missing required fields"}), 400

    # Log progress
    progress_log = ProgressLog(
        member_id=member_id,
        weight=weight,
        reps=reps,
        sets=sets,
        date=datetime.now()
    )
    db.session.add(progress_log)
    db.session.commit()

    return jsonify({"message": "Progress logged", "progress": progress_log_schema.dump(progress_log)})


@app.route("/book-class", methods=["POST"])
@jwt_required()
def book_class():
    data = request.get_json()
    class_id = data.get("class_id")
    start_time = data.get("start_time")
    end_time = data.get("end_time")

    # Get the member ID from the JWT token
    member_id = get_jwt_identity()

    if not class_id or not start_time or not end_time:
        return jsonify({"msg": "Missing required fields"}), 400

    # Check for existing bookings using member_id, NOT user_id
    existing_booking = Booking.query.filter_by(member_id=member_id, class_id=class_id).first()

    if existing_booking:
        return jsonify({"msg": "You have already booked this class"}), 400

    # Ensure no double booking (unique combination of class, start time, and end time)
    existing_booking_time = Booking.query.filter(
        Booking.class_id == class_id,
        Booking.start_time <= end_time,
        Booking.end_time >= start_time
    ).first()

    if existing_booking_time:
        return jsonify({"msg": "This class is already booked at the selected time"}), 400

    # Fetch trainer_id based on class_id, assuming it's available
    class_info = Class.query.get(class_id)
    if not class_info or not class_info.trainer_id:
        return jsonify({"msg": "Trainer not assigned to this class"}), 400

    trainer_id = class_info.trainer_id  # Use the trainer assigned to the class

    # Create a new booking with trainer_id
    new_booking = Booking(
        class_id=class_id,
        trainer_id=trainer_id,  # Add the trainer_id
        member_id=member_id,
        start_time=start_time,
        end_time=end_time
    )

    db.session.add(new_booking)
    db.session.commit()

    return jsonify({"msg": "Class booked successfully", "booking": new_booking.id}), 201

@app.route("/bookings", methods=["GET"])
@jwt_required()
def get_bookings():
    member_id = request.args.get("member_id")
    if not member_id:
        return jsonify({"msg": "Member ID is required"}), 400

    # Ensure the member exists
    member = Member.query.get(member_id)
    if not member:
        return jsonify({"msg": "Member not found"}), 404

    # Fetch bookings for the member
    bookings = Booking.query.filter_by(member_id=member_id).all()
    return jsonify({"bookings": [{
        "id": booking.id,
        "class_id": booking.class_id,
        "class_": {
            "id": booking.class_.id,
            "name": booking.class_.name,
            "description": booking.class_.description
        },
        "start_time": booking.start_time.isoformat(),
        "end_time": booking.end_time.isoformat()
    } for booking in bookings]})

@app.route("/members", methods=["GET"])
@jwt_required()
def get_members():
    # Logic to fetch all members
    members = Member.query.all()
    return jsonify(members_schema.dump(members))  # Assuming members_schema is defined

@app.route("/progress/<int:member_id>", methods=["GET"])
@jwt_required()
def get_progress_logs(member_id):
    # Logic to get progress logs for the specified member
    progress_logs = ProgressLog.query.filter_by(member_id=member_id).all()
    return jsonify(progress_logs_schema.dump(progress_logs))  # Assuming progress_logs_schema is defined

@app.route('/workout-plans', methods=["GET"])
@jwt_required()  # Ensure the user is logged in (JWT token required)
def get_workout_plans():
    trainer_id = get_jwt_identity()  # Get trainer's ID from the JWT token

    try:
        # Retrieve all workout plans for the trainer
        workout_plans = WorkoutPlan.query.filter_by(trainer_id=trainer_id).all()

        if not workout_plans:
            return jsonify({"message": "No workout plans found for this trainer."}), 404

        # Serialize the workout plans data
        workout_plans_data = [
            {
                "id": plan.id,
                "name": plan.name,
                "description": plan.description
            }
            for plan in workout_plans
        ]

        return jsonify({"workout_plans": workout_plans_data}), 200

    except Exception as e:
        app.logger.error(f"Error retrieving workout plans: {e}")
        return jsonify({"message": "An error occurred while retrieving the workout plans.", "error": str(e)}), 500


@app.route("/progress/<int:id>", methods=["PUT"])
@jwt_required()
def update_progress_log(id):
    data = request.get_json()

    weight = data.get('weight')
    reps = data.get('reps')
    sets = data.get('sets')

    if not weight or not reps or not sets:
        return jsonify({"message": "Missing required fields"}), 400

    # Fetch the progress log to update
    progress_log = ProgressLog.query.get(id)
    if not progress_log:
        return jsonify({"message": "Progress log not found"}), 404

    # Ensure the current user owns this progress log
    current_user = get_jwt_identity()
    if progress_log.member_id != current_user:
        return jsonify({"message": "You can only update your own progress log"}), 403

    # Update the progress log
    progress_log.weight = weight
    progress_log.reps = reps
    progress_log.sets = sets
    progress_log.date = datetime.now()  # Update the date to current time

    db.session.commit()

    return jsonify({"message": "Progress log updated", "progress": progress_log_schema.dump(progress_log)}), 200


@app.route('/members/<int:member_id>', methods=['DELETE'])
@jwt_required()
def delete_member(member_id):
    current_user_id = get_jwt_identity()
    
    # Fetch the current user (assuming "Member" is your user model)
    current_user = Member.query.get(current_user_id)  # Use Member instead of User

    # Fetch the member to be deleted
    member = Member.query.get(member_id)
    if not member:
        return jsonify({"message": "Member not found"}), 404

    # Ensure the user is either an admin, a trainer, or deleting their own account
    if current_user_id != member_id and current_user.role.name.lower() not in ["admin", "trainer"]:
        return jsonify({"message": "You are not authorized to delete this member."}), 403

    # Delete the member
    try:
        db.session.delete(member)
        db.session.commit()
    except Exception as e:
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500

    return jsonify({"message": "Member deleted successfully"}), 200

@app.route('/members/<int:member_id>', methods=['PUT'])
@jwt_required()
def update_member(member_id):
    current_user_id = get_jwt_identity()  # Get the current logged-in user's ID
    current_user = Member.query.get(current_user_id)  # Fetch the current user's data
    
    # Ensure the current user is either updating their own details or is an admin or trainer
    if current_user.id != member_id and current_user.role.name.lower() not in ['admin', 'trainer']:
        return jsonify({"message": "You can only update your own details or be an admin/trainer to update others' details"}), 403

    # Fetch the member to be updated
    member = Member.query.get(member_id)
    if not member:
        return jsonify({"message": "Member not found"}), 404

    # Get data from the request
    data = request.get_json()

    # Update fields only if they are provided in the request
    name = data.get("name")
    email = data.get("email")
    password = data.get("password")

    if name:
        member.name = name
    if email:
        # Check if the email is already in use by another member
        existing_member = Member.query.filter_by(email=email).first()
        if existing_member and existing_member.id != member_id:
            return jsonify({"message": "Email already in use by another member"}), 400
        member.email = email
    if password:
        # Hash the new password
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
        member.password = hashed_password

    # Commit the changes to the database
    db.session.commit()

    return jsonify({"message": "Member details updated successfully", "member": member_schema.dump(member)}), 200


@app.route('/workout_plan/<int:workout_plan_id>/add_member', methods=['POST'])
@jwt_required()
def add_member_to_workout(workout_plan_id):
    # Get the current user's ID (trainer)
    trainer_id = get_jwt_identity()

    # Retrieve the member and workout plan details from the database
    member_id = request.json.get('member_id')

    # Ensure the user is a trainer
    trainer = Member.query.filter_by(id=trainer_id).join(Role).filter(Role.name.ilike('trainer')).first()
    if not trainer:
        return jsonify({"message": "Unauthorized. Only trainers can add members to workout plans."}), 403

    # Ensure the workout plan exists and is associated with the trainer
    workout_plan = WorkoutPlan.query.filter_by(id=workout_plan_id, trainer_id=trainer_id).first()
    if not workout_plan:
        return jsonify({"message": "Workout plan not found or you are not the trainer of this plan."}), 404

    # Ensure the member exists
    member = Member.query.filter_by(id=member_id).first()
    if not member:
        return jsonify({"message": "Member not found."}), 404

    # Check if the member is already part of the workout plan
    existing_member_workout = MemberWorkout.query.filter_by(member_id=member_id, workout_plan_id=workout_plan_id).first()
    if existing_member_workout:
        return jsonify({"message": "Member is already part of this workout plan."}), 400

    # Add the member to the workout plan by creating an entry in the MemberWorkout table
    new_member_workout = MemberWorkout(member_id=member_id, workout_plan_id=workout_plan_id)
    db.session.add(new_member_workout)
    db.session.commit()

    return jsonify({"message": "Member successfully added to the workout plan."}), 201


@app.route("/progress/<int:id>", methods=["DELETE"])
@jwt_required()
def delete_progress_log(id):
    # Fetch the progress log to delete
    progress_log = ProgressLog.query.get(id)
    if not progress_log:
        return jsonify({"message": "Progress log not found"}), 404

    # Ensure the current user owns this progress log
    current_user = get_jwt_identity()
    if progress_log.member_id != current_user:
        return jsonify({"message": "You can only delete your own progress log"}), 403

    # Delete the progress log
    db.session.delete(progress_log)
    db.session.commit()

    return jsonify({"message": "Progress log deleted successfully"}), 200

@app.route("/assign_member_to_class", methods=["POST"])
@jwt_required()
def assign_member_to_class():
    # Get the trainer's ID from the JWT token
    trainer_id = get_jwt_identity()  # No need for ['id']
    
    # Get the class ID and member ID from the request body
    data = request.get_json()
    member_id = data.get('member_id')
    class_id = data.get('class_id')

    if not member_id or not class_id:
        return jsonify({"message": "Member ID and Class ID are required"}), 400
    
    # Verify the trainer is the trainer for this class
    class_ = Class.query.filter_by(id=class_id, trainer_id=trainer_id).first()
    if not class_:
        return jsonify({"message": "You are not authorized to assign members to this class"}), 403
    
    # Ensure the member exists
    member = Member.query.get(member_id)
    if not member:
        return jsonify({"message": "Member not found"}), 404

    # Check if the member is already in the class
    existing_member_class = MemberClass.query.filter_by(member_id=member_id, class_id=class_id).first()
    if existing_member_class:
        return jsonify({"message": "Member is already in this class"}), 400

    # Assign the member to the class
    member_class = MemberClass(member_id=member_id, class_id=class_id)
    db.session.add(member_class)
    db.session.commit()

    # Return success message
    return jsonify({"message": "Member successfully assigned to the class"}), 201


if __name__ == '__main__':
    app.run(debug=True)
