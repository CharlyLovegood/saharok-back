from flask import Flask
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from flask_migrate import Migrate
from flask_mail import Mail
from flask_socketio import SocketIO

from flask_socketio import join_room, leave_room, emit

app = Flask(__name__)
app.config.from_object('config.DevConfig')
cors = CORS(app, resources={r"/*": {"origins": "*"}})
api = Api(app)
jwt = JWTManager(app)
sio = SocketIO(app, cors_allowed_origins="*")

db = SQLAlchemy(app)
migrate = Migrate(app, db)

mail = Mail(app)

import models, resources
from models import DeskModel

api.add_resource(resources.UserRegistration, '/registration')
api.add_resource(resources.UserLogin, '/login')
api.add_resource(resources.UserLogoutAccess, '/logout/access')
api.add_resource(resources.UserLogoutRefresh, '/logout/refresh')
api.add_resource(resources.TokenRefresh, '/token/refresh')
api.add_resource(resources.AllUsers, '/users')
api.add_resource(resources.GetUser, '/user/<string:id>')
api.add_resource(resources.GetCurrentUser, '/current-user')
api.add_resource(resources.ConfirmEmail, '/confirm_email')

api.add_resource(resources.CreateDesk, '/create-desk')
api.add_resource(resources.EditDesk, '/edit-desk')
api.add_resource(resources.DeleteDesk, '/delete-desk')
api.add_resource(resources.AllDesks, '/desks')
api.add_resource(resources.GetDesk, '/desk/<string:id>')

api.add_resource(resources.PinCard, '/pin-card')
api.add_resource(resources.DeleteCard, '/delete-card')
api.add_resource(resources.AllCards, '/cards')


@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    return models.RevokedTokenModel.is_jti_blacklisted(jti)



@sio.on('join-desk')
def join(data):
    room = DeskModel.find_by_public_id(data['desk']).id
    join_room(room)
    emit('connect', ' has entered the room.', room=room)


@sio.on('pin-to-desk')
def desk(data):
    room = DeskModel.find_by_public_id(data['desk']).id
    card = data['card']
    emit('pin-card', card, room=room, include_self=False)


@sio.on('delete-from-desk')
def desk(data):
    room = DeskModel.find_by_public_id(data['desk']).id
    card_id = data['card_id']
    emit('delete-card', card_id, room=room, include_self=False)


@sio.on('leave-desk')
def on_leave(data):
    room = DeskModel.find_by_public_id(data['desk']).id
    leave_room(room)
