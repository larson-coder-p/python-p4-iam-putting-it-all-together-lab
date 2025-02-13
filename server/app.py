from flask import Flask, request, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'super-secret-key'  # Change this in production

db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)

####################################
# Models
####################################

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    _password_hash = db.Column(db.String, nullable=False)
    image_url = db.Column(db.String)
    bio = db.Column(db.String)
    
    # A user can have many recipes.
    recipes = db.relationship('Recipe', backref='user', lazy=True)
    
    # Write-only password setter. Attempts to read will raise an error.
    @property
    def password_hash(self):
        raise AttributeError("password: write-only field")
    
    @password_hash.setter
    def password_hash(self, password):
        self._password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    
    def check_password(self, password):
        return bcrypt.check_password_hash(self._password_hash, password)
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'image_url': self.image_url,
            'bio': self.bio
        }


class Recipe(db.Model):
    __tablename__ = 'recipes'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String, nullable=False)
    minutes_to_complete = db.Column(db.Integer)
    
    # Each recipe belongs to a user.
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'instructions': self.instructions,
            'minutes_to_complete': self.minutes_to_complete,
            'user': self.user.to_dict() if self.user else None
        }

####################################
# Routes / Resources
####################################

# --- Sign Up ---
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()

    username = data.get('username')
    password = data.get('password')
    image_url = data.get('image_url')
    bio = data.get('bio')

    # Validate presence of required fields.
    if not username or not password:
        return jsonify({'errors': ['Username and password required']}), 422

    # Ensure username is unique.
    if User.query.filter_by(username=username).first():
        return jsonify({'errors': ['Username already taken']}), 422

    # Create the new user.
    user = User(username=username, image_url=image_url, bio=bio)
    user.password_hash = password  # This will encrypt the password.
    
    db.session.add(user)
    db.session.commit()

    # Save the user_id in the session for auto-login.
    session['user_id'] = user.id

    return jsonify(user.to_dict()), 201

# --- Auto-Login / Check Session ---
@app.route('/check_session', methods=['GET'])
def check_session():
    user_id = session.get('user_id')
    if user_id:
        user = User.query.get(user_id)
        if user:
            return jsonify(user.to_dict()), 200
    return jsonify({'error': 'Unauthorized'}), 401

# --- Login ---
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        session['user_id'] = user.id
        return jsonify(user.to_dict()), 200

    return jsonify({'error': 'Invalid username or password'}), 401

# --- Logout ---
@app.route('/logout', methods=['DELETE'])
def logout():
    if session.get('user_id'):
        session.pop('user_id')
        return '', 204
    return jsonify({'error': 'Unauthorized'}), 401

# --- Recipe List & Recipe Creation ---
@app.route('/recipes', methods=['GET', 'POST'])
def recipes():
    # Ensure the user is logged in.
    if not session.get('user_id'):
        return jsonify({'error': 'Unauthorized'}), 401

    # GET: Return a list of recipes.
    if request.method == 'GET':
        recipes = Recipe.query.all()
        recipes_list = [recipe.to_dict() for recipe in recipes]
        return jsonify(recipes_list), 200

    # POST: Create a new recipe.
    if request.method == 'POST':
        data = request.get_json()

        title = data.get('title')
        instructions = data.get('instructions')
        minutes_to_complete = data.get('minutes_to_complete')

        # Validate required fields.
        errors = []
        if not title:
            errors.append("Title is required")
        if not instructions:
            errors.append("Instructions are required")
        elif len(instructions) < 50:
            errors.append("Instructions must be at least 50 characters long")

        if errors:
            return jsonify({'errors': errors}), 422

        user_id = session.get('user_id')
        new_recipe = Recipe(
            title=title,
            instructions=instructions,
            minutes_to_complete=minutes_to_complete,
            user_id=user_id
        )
        db.session.add(new_recipe)
        db.session.commit()

        return jsonify(new_recipe.to_dict()), 201

if __name__ == '__main__':
    app.run(debug=True)
