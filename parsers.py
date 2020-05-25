from flask_restful import reqparse

login_parser = reqparse.RequestParser()
login_parser.add_argument('email', help='This field cannot be blank', required=True)
login_parser.add_argument('password', help='This field cannot be blank', required=True)

registration_parser = reqparse.RequestParser()
registration_parser.add_argument('username', help='This field cannot be blank', required=True)
registration_parser.add_argument('password', help='This field cannot be blank', required=True)
registration_parser.add_argument('email', help='This field cannot be blank', required=True)

confirm_email_parser = reqparse.RequestParser()
confirm_email_parser.add_argument('token', help='This field cannot be blank', required=True)
confirm_email_parser.add_argument('empty', required=False)

desk_parser = reqparse.RequestParser()
desk_parser.add_argument('name', help='This field cannot be blank', required=True)
desk_parser.add_argument('state', help='This field cannot be blank', required=True)

delete_desk_parser = reqparse.RequestParser()
delete_desk_parser.add_argument('id', help='This field cannot be blank', required=True)

get_desk_parser = reqparse.RequestParser()
get_desk_parser.add_argument('id', help='This field cannot be blank', required=True)

edit_desk_parser = reqparse.RequestParser()
edit_desk_parser.add_argument('id', help='This field cannot be blank', required=True)
edit_desk_parser.add_argument('name', help='This field cannot be blank', required=True)
edit_desk_parser.add_argument('state', help='This field cannot be blank', required=True)

card_parser = reqparse.RequestParser()
card_parser.add_argument('content', help='This field cannot be blank', required=True)
card_parser.add_argument('type', help='This field cannot be blank', required=True)
card_parser.add_argument('desk_id', help='This field cannot be blank', required=True)

delete_card_parser = reqparse.RequestParser()
delete_card_parser.add_argument('id', help='This field cannot be blank', required=True)