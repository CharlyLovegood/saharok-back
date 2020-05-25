from run import db
from passlib.hash import pbkdf2_sha256 as sha256
from config import Config



class UserModel(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    profile_confirmed = db.Column(db.Boolean(), default=False)


    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    def update_db(self):
        db.session.commit()

    @classmethod
    def find_by_username(cls, username):
        return cls.query.filter_by(username=username).first()

    @classmethod
    def find_by_id(cls, id):
        return cls.query.filter_by(id=id).first()

    @classmethod
    def find_by_email(cls, email):
        return cls.query.filter_by(email=email).first()

    @classmethod
    def return_all(cls):
        def to_json(x):
            return {
                'username': x.username,
                'password': x.password,
                'email': x.email
            }
        return {'users': list(map(lambda x: to_json(x), UserModel.query.all()))}

    @classmethod
    def delete_all(cls):
        try:
            num_rows_deleted = db.session.query(cls).delete()
            db.session.commit()
            return {'message': '{} row(s) deleted'.format(num_rows_deleted)}
        except:
            return {'message': 'Something went wrong'}

    @staticmethod
    def generate_hash(password):
        return sha256.hash(password)

    @staticmethod
    def verify_hash(password, hash):
        return sha256.verify(password, hash)


class RevokedTokenModel(db.Model):
    __tablename__ = 'revoked_tokens'
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(120))

    def add(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def is_jti_blacklisted(cls, jti):
        query = cls.query.filter_by(jti=jti).first()
        return bool(query)



class DeskModel(db.Model):
    __tablename__ = 'desks'

    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(200), unique=True)
    name = db.Column(db.String(120), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey(UserModel.id, ondelete='CASCADE'), nullable=False)
    state = db.Column(db.String(120), nullable=False)

    cards = db.relationship('CardModel', cascade="all, delete-orphan")


    def save_to_db(self):
        db.session.add(self)
        db.session.commit()


    def update_db(self):
        db.session.commit()


    def generate_public_id(self):
        public_id = sha256.hash('{}{}'.format(self.id, Config.SALT)).replace('/', '@')\
                                                                    .replace('&', '1')\
                                                                    .replace('?', '5')
        self.public_id = public_id
        db.session.commit()


    @classmethod
    def find_by_user(cls, id):
        return cls.query.filter_by(author_id=id).all()


    @classmethod
    def find_by_public_id(cls, id):
        return cls.query.filter_by(public_id=id).first()


    @classmethod
    def delete_from_db(cls, id):
        db.session.query(cls).filter(cls.id == id).delete()
        db.session.commit()


    @classmethod
    def return_all(cls):
        def to_json(x):
            return {
                'id': x.id,
                'public_id': x.public_id,
                'name': x.name,
                'author_id': x.author_id,
                'state': x.state
            }
        return {'desks': list(map(lambda x: to_json(x), DeskModel.query.all()))}


    @classmethod
    def delete_all(cls):
        try:
            num_rows_deleted = db.session.query(cls).delete()
            db.session.commit()
            return {'message': '{} row(s) deleted'.format(num_rows_deleted)}
        except:
            return {'message': 'Something went wrong'}


    @classmethod
    def to_json(self, x):
        return {
            'public_id': x.public_id,
            'name': x.name,
            'state': x.state
        }



class CardModel(db.Model):
    __tablename__ = 'cards'

    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey(UserModel.id), nullable=False)
    content = db.Column(db.String(600), nullable=False)
    type = db.Column(db.String(120), nullable=False)
    desk_id = db.Column(db.Integer, db.ForeignKey(DeskModel.id, ondelete='CASCADE'), nullable=False)

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()


    def update_db(self):
        db.session.commit()


    @classmethod
    def to_json(self, x, author_id):
        return {
            'id': x.id,
            'content': x.content,
            'author_id': x.author_id,
            'type': x.type,
            'is_author': (x.author_id == author_id)
        }


    @classmethod
    def delete_from_db(cls, id):
        db.session.query(cls).filter(cls.id == id).delete()
        db.session.commit()


    @classmethod
    def delete_from_db_by_desk(cls, desk_id):
        db.session.query(cls).filter(cls.desk_id == desk_id).delete()
        db.session.commit()


    @classmethod
    def return_all(cls):
        def to_json(x):
            return {
                'id': x.id,
                'content': x.content,
                'author_id': x.author_id,
                'type': x.type,
                'desk_id': x.desk_id
            }
        return {'cards': list(map(lambda x: to_json(x), CardModel.query.all()))}


    @classmethod
    def delete_all(cls):
        try:
            num_rows_deleted = db.session.query(cls).delete()
            db.session.commit()
            return {'message': '{} row(s) deleted'.format(num_rows_deleted)}
        except:
            return {'message': 'Something went wrong'}