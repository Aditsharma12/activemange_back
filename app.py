from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
from bson.objectid import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import datetime
import urllib.parse
import certifi
import os

app = Flask(__name__)
CORS(app)

app.config['JWT_SECRET_KEY'] = 'super-secret-class-key-2428' 
jwt = JWTManager(app)

# MongoDB Configuration
username = urllib.parse.quote_plus('adit2428cs1345_db_user')
password = urllib.parse.quote_plus('adit@1234') # UPDATE THIS
MONGO_URI = f"mongodb+srv://{username}:{password}@cluster0.452pmlf.mongodb.net/?appName=Cluster0"

client = MongoClient(MONGO_URI, tlsCAFile=certifi.where())
db = client['class_management_db']

users_col = db['users']
groups_col = db['groups']
invites_col = db['invites']

def format_doc(doc):
    if not doc: return None
    doc['id'] = str(doc['_id'])
    del doc['_id']
    for key in ['group_ids', 'member_ids']:
        if key in doc: doc[key] = [str(i) for i in doc[key]]
    for key in ['creator_id', 'group_id', 'sender_id', 'receiver_id']:
        if key in doc and doc[key]: doc[key] = str(doc[key])
    if 'password_hash' in doc: del doc['password_hash']
    for key, value in doc.items():
        if isinstance(value, datetime.datetime): doc[key] = value.isoformat()
    return doc

# --- AUTH & PROFILES ---
@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.json
    
    # 1. Mandatory Phone Number Check
    phone_number = data.get('phone_number')
    if not phone_number:
        return jsonify({"error": "Phone number is mandatory"}), 400

    if users_col.find_one({"email": data.get('email')}):
        return jsonify({"error": "Email already exists"}), 400
        
    new_user = {
        "name": data.get('name'),
        "roll_number": data.get('roll_number'),
        "email": data.get('email'),
        "phone_number": phone_number, # 2. Save Phone Number
        "password_hash": generate_password_hash(data.get('password')),
        "about": "Hey there! I am using Class Manager.", 
        "group_ids": [],
        "last_login": datetime.datetime.utcnow()
    }
    result = users_col.insert_one(new_user)
    return jsonify({"message": "Registered", "user_id": str(result.inserted_id)}), 201

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json
    user = users_col.find_one({"email": data.get('email')})
    if user and check_password_hash(user['password_hash'], data.get('password')):
        users_col.update_one({"_id": user['_id']}, {"$set": {"last_login": datetime.datetime.utcnow()}})
        user['last_login'] = datetime.datetime.utcnow()
        access_token = create_access_token(identity=str(user['_id']), expires_delta=datetime.timedelta(days=7))
        return jsonify({"access_token": access_token, "user": format_doc(user)}), 200
    return jsonify({"error": "Invalid credentials"}), 401

@app.route('/api/users/profile', methods=['PUT'])
@jwt_required()
def update_profile():
    current_user_id = get_jwt_identity()
    data = request.json
    users_col.update_one(
        {"_id": ObjectId(current_user_id)},
        {"$set": {
            "name": data.get('name'),
            "roll_number": data.get('roll_number'),
            "phone_number": data.get('phone_number'), # 3. Update Phone Number
            "about": data.get('about')
        }}
    )
    updated_user = users_col.find_one({"_id": ObjectId(current_user_id)})
    return jsonify(format_doc(updated_user)), 200

# --- DIRECTORY ---
@app.route('/api/directory', methods=['GET'])
@jwt_required()
def get_directory():
    users = [format_doc(u) for u in users_col.find({}, {"password_hash": 0})]
    return jsonify(users), 200

# --- FULL CRUD FOR GROUPS ---
@app.route('/api/groups', methods=['POST'])
@jwt_required()
def create_group():
    current_user_id = get_jwt_identity()
    data = request.json
    new_group = {
        "name": data.get('name'), "purpose": data.get('purpose'),
        "creator_id": ObjectId(current_user_id), "member_ids": [ObjectId(current_user_id)],
        "max_capacity": data.get('max_capacity', 10)
    }
    result = groups_col.insert_one(new_group)
    users_col.update_one({"_id": ObjectId(current_user_id)}, {"$addToSet": {"group_ids": result.inserted_id}})
    return jsonify(format_doc(groups_col.find_one({"_id": result.inserted_id}))), 201

@app.route('/api/groups/my_groups', methods=['GET'])
@jwt_required()
def my_groups():
    current_user_id = get_jwt_identity()
    groups = [format_doc(g) for g in groups_col.find({"member_ids": ObjectId(current_user_id)})]
    return jsonify(groups), 200

@app.route('/api/groups/<group_id>', methods=['GET'])
@jwt_required()
def get_group_details(group_id):
    group = groups_col.find_one({"_id": ObjectId(group_id)})
    if not group: return jsonify({"error": "Not found"}), 404
    members = list(users_col.find({"_id": {"$in": group.get('member_ids', [])}}, {"password_hash": 0}))
    formatted_group = format_doc(group)
    formatted_group['members'] = [format_doc(m) for m in members]
    return jsonify(formatted_group), 200

@app.route('/api/groups/<group_id>', methods=['PUT'])
@jwt_required()
def update_group(group_id):
    current_user_id = get_jwt_identity()
    group = groups_col.find_one({"_id": ObjectId(group_id)})
    if str(group['creator_id']) != current_user_id:
        return jsonify({"error": "Only the creator can edit this group"}), 403
    data = request.json
    groups_col.update_one({"_id": ObjectId(group_id)}, {"$set": {"name": data.get('name'), "purpose": data.get('purpose')}})
    return jsonify({"message": "Group updated"}), 200

@app.route('/api/groups/<group_id>', methods=['DELETE'])
@jwt_required()
def delete_or_leave_group(group_id):
    current_user_id = get_jwt_identity()
    group = groups_col.find_one({"_id": ObjectId(group_id)})
    if str(group['creator_id']) == current_user_id:
        groups_col.delete_one({"_id": ObjectId(group_id)})
        users_col.update_many({}, {"$pull": {"group_ids": ObjectId(group_id)}})
        return jsonify({"message": "Group deleted permanently"}), 200
    else:
        groups_col.update_one({"_id": ObjectId(group_id)}, {"$pull": {"member_ids": ObjectId(current_user_id)}})
        users_col.update_one({"_id": ObjectId(current_user_id)}, {"$pull": {"group_ids": ObjectId(group_id)}})
        return jsonify({"message": "You left the group"}), 200

# --- INVITES ---
@app.route('/api/invites', methods=['POST'])
@jwt_required()
def send_invite():
    current_user_id = get_jwt_identity()
    data = request.json
    receiver_id = ObjectId(data.get('receiver_id'))
    group_id = ObjectId(data.get('group_id'))
    group = groups_col.find_one({"_id": group_id})
    if receiver_id in group.get('member_ids', []): return jsonify({"error": "User already in group"}), 400
    if invites_col.find_one({"group_id": group_id, "receiver_id": receiver_id, "status": "pending"}): return jsonify({"error": "Invite already pending"}), 400

    invites_col.insert_one({
        "group_id": group_id, "sender_id": ObjectId(current_user_id),
        "receiver_id": receiver_id, "status": "pending",
        "timestamp": datetime.datetime.utcnow(), "group_name": group['name']
    })
    return jsonify({"message": "Invite sent"}), 201

@app.route('/api/invites/pending', methods=['GET'])
@jwt_required()
def get_pending_invites():
    current_user_id = get_jwt_identity()
    invites = [format_doc(i) for i in invites_col.find({"receiver_id": ObjectId(current_user_id), "status": "pending"}).sort("timestamp", -1)]
    return jsonify(invites), 200

@app.route('/api/invites/<invite_id>/respond', methods=['POST'])
@jwt_required()
def respond_invite(invite_id):
    current_user_id = get_jwt_identity()
    action = request.json.get('action')
    invite = invites_col.find_one({"_id": ObjectId(invite_id), "receiver_id": ObjectId(current_user_id)})
    if not invite: return jsonify({"error": "Not found"}), 404
        
    if action == "accept":
        groups_col.update_one({"_id": invite['group_id']}, {"$addToSet": {"member_ids": ObjectId(current_user_id)}})
        users_col.update_one({"_id": ObjectId(current_user_id)}, {"$addToSet": {"group_ids": invite['group_id']}})
        invites_col.update_one({"_id": ObjectId(invite_id)}, {"$set": {"status": "accepted"}})
        return jsonify({"message": "Accepted!"}), 200
    elif action == "decline":
        invites_col.update_one({"_id": ObjectId(invite_id)}, {"$set": {"status": "declined"}})
        return jsonify({"message": "Declined."}), 200
    return jsonify({"error": "Invalid action"}), 400

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False)