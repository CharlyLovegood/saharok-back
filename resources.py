from flask_restful import Resource, reqparse
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from flask_mail import Message
import datetime

from models import UserModel, RevokedTokenModel, DeskModel, CardModel
from run import mail
from parsers import *

safe_serializer = URLSafeTimedSerializer("secret-key")

class UserRegistration(Resource):
    def post(self):
        data = registration_parser.parse_args()

        if UserModel.find_by_username(data['username']):
            return {'message': 'User {} already exists'.format(data['username'])}, 409

        new_user = UserModel(
            username=data['username'],
            password=UserModel.generate_hash(data['password']),
            email=data['email']
        )

        try:
            email = data['email']
            token = safe_serializer.dumps(email, salt='email-confirm-salt')
            msg = Message('Confirm email', sender='aloha.saharok@gmail.com', recipients=[email])

            link = "http://localhost:3000/email-confirm/{token}".format(token=token)
            msg.body = 'Your confirm link {}'.format(link)
            mail.send(msg)

            new_user.save_to_db()

            return {
                'message': 'User {} was created, and confirm link has been sent'.format(data['username'])
            }
        except:
            return {'message': 'Something went wrong'}, 500


class UserLogin(Resource):
    def post(self):
        data = login_parser.parse_args()
        current_user = UserModel.find_by_email(data['email'])
        if not current_user:
            return {'message': 'Wrong credentials'}, 401

        if UserModel.verify_hash(data['password'], current_user.password):
            access_token = create_access_token(identity=data['email'])
            refresh_token = create_refresh_token(identity=data['email'])

            if not current_user.profile_confirmed:
                try:
                    email = current_user.email
                    token = safe_serializer.dumps(email, salt='email-confirm-salt')
                    msg = Message('Confirm email', sender='aloha.saharok@gmail.com', recipients=[email])

                    link = "http://localhost:3000/email-confirm/{token}".format(token=token)
                    msg.body = 'Your confirm link {}'.format(link)
                    mail.send(msg)

                    return {'message': 'Confirm link has been sent to {}'.format(email)},
                except:
                    return {'message': 'Something went wrong'}, 500

            return {
                'message': 'Logged in as {}'.format(current_user.username),
                'access_token': access_token,
                'refresh_token': refresh_token
            }
        else:
            return {'message': 'Wrong credentials'}, 401


class UserLogoutAccess(Resource):
    @jwt_required
    def post(self):
        jti = get_raw_jwt()['jti']
        try:
            revoked_token = RevokedTokenModel(jti=jti)
            revoked_token.add()
            return {'message': 'Access token has been revoked'}
        except:
            return {'message': 'Something went wrong'}, 500


class UserLogoutRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        jti = get_raw_jwt()['jti']
        try:
            revoked_token = RevokedTokenModel(jti=jti)
            revoked_token.add()
            return {'message': 'Refresh token has been revoked'}
        except:
            return {'message': 'Something went wrong'}, 500


class TokenRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        current_user = get_jwt_identity()
        expires = datetime.timedelta(minutes=15)
        access_token = create_access_token(identity=current_user, expires_delta=expires)

        return {'access_token': access_token}


class AllUsers(Resource):
    def get(self):
        return UserModel.return_all()

    def delete(self):
        return UserModel.delete_all()


class ConfirmEmail(Resource):
    def post(self):

        data = confirm_email_parser.parse_args()
        token = data['token']

        try:
            email = safe_serializer.loads(token, salt='email-confirm-salt', max_age=600)

            current_user = UserModel.find_by_email(email)
            current_user.profile_confirmed = True
            current_user.update_db()

            access_token = create_access_token(identity=email)
            refresh_token = create_refresh_token(identity=email)
            return {
                'message': 'Logged in as {}'.format(email),
                'access_token': access_token,
                'refresh_token': refresh_token
            }
        except SignatureExpired:
            return {'message': 'Refresh token has expired'}, 500
        return {'message': 'Something went wrong'}, 500


class GetCurrentUser(Resource):
    @jwt_required
    def get(self):
        user_email = get_jwt_identity()
        user = UserModel.find_by_email(user_email)

        desks = DeskModel.find_by_user(user.id)
        json_desks = list(map(lambda x: DeskModel.to_json(x), desks))

        return {
            'username': user.username,
            'desks': json_desks
        }


class GetUser(Resource):
    @jwt_required
    def get(self, id):
        current_user_email = get_jwt_identity()
        current_user = UserModel.find_by_email(current_user_email)
        user = UserModel.find_by_id(id)

        if not user:
            return {'message': 'User {} doesn\'t exist'.format(id)}, 500

        if (user.id == current_user.id):
            desks = DeskModel.find_by_user(user.id)
            json_desks = list(map(lambda x: DeskModel.to_json(x), desks))

            return {
                'username': user.username,
                'desks': json_desks
            }

        return {
            'username': user.username,
        }


class CreateDesk(Resource):
    @jwt_required
    def post(self):
        data = desk_parser.parse_args()
        author_email = get_jwt_identity()
        author_id = UserModel.find_by_email(author_email).id

        new_desk = DeskModel(
            name=data['name'],
            author_id=author_id,
            state=data['state']
        )

        try:
            new_desk.save_to_db()
            new_desk.generate_public_id()
        except:
            return {'message': 'Something went wrong'}, 500

        return {
            'message': 'Desk created',
            'public_id': new_desk.public_id
        }


class EditDesk(Resource):
    @jwt_required
    def post(self):
        data = edit_desk_parser.parse_args()
        user_email = get_jwt_identity()
        user_id = UserModel.find_by_email(user_email).id
        desk = DeskModel.find_by_public_id(data['id'])

        if not desk:
            return {'message': 'Desk doesn\'t exist'}, 401

        if desk.author_id != user_id:
            return {'message': 'Forbiden'}, 403

        desk.name = data['name']
        desk.state = data['state']
        desk.update_db()

        return {
            'name': desk.name,
            'state': desk.state,
        }


class GetDesk(Resource):
    @jwt_required
    def get(self, id):
        user_email = get_jwt_identity()
        user_id = UserModel.find_by_email(user_email).id

        desk = DeskModel.find_by_public_id(id)
        cards = list(map(lambda x: CardModel.to_json(x, user_id), desk.cards))

        is_author = (desk.author_id == user_id)

        return {
            'name': desk.name,
            'author_id': desk.author_id,
            'state': desk.state,
            'cards': cards,
            'is_author': is_author
        }


class AllDesks(Resource):
    def get(self):
        return DeskModel.return_all()

    def delete(self):
        return DeskModel.delete_all()


class DeleteDesk(Resource):
    @jwt_required
    def post(self):
        data = delete_desk_parser.parse_args()
        desk_id = data['id']
        try:
            DeskModel.delete_from_db(desk_id)
            CardModel.delete_from_db_by_desk(desk_id)
        except:
            return {'message': 'Something went wrong'}, 500

        return {'message': 'Desk deleted'}


class DeleteCard(Resource):
    @jwt_required
    def post(self):
        data = delete_card_parser.parse_args()
        try:
            CardModel.delete_from_db(data['id'])
        except:
            return {'message': 'Something went wrong'}, 500

        return {'message': 'Card deleted'}


class PinCard(Resource):
    @jwt_required
    def post(self):
        data = card_parser.parse_args()
        author_email = get_jwt_identity()
        author_id = UserModel.find_by_email(author_email).id
        desk_id = DeskModel.find_by_public_id(data['desk_id']).id

        new_card = CardModel(
            author_id=author_id,
            content=data['content'],
            type=data['type'],
            desk_id=desk_id
        )

        try:
            new_card.save_to_db()
        except:
            return {'message': 'Something went wrong'}, 500
        return {
            'message': 'Card pinned',
            'content': new_card.content,
            'id': new_card.id
        }


class AllCards(Resource):
    def get(self):
        return CardModel.return_all()

    def delete(self):
        return CardModel.delete_all()

