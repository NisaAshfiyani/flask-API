from flask import *
from flask_restx import Resource, Api, reqparse
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import jwt
import cv2
app = Flask(__name__) # Instantiation of Flask object.
api = Api(app)        # Instantiation of Flask-RESTX object.
mail = Mail(app)
camera = cv2.VideoCapture('http://192.168.15.251')

############################
##### BEGIN: Database #####
##########################
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root:@127.0.0.1:3306/webservice"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = True

app.config['MAIL_SERVER'] = "smtp.gmail.com"
app.config['MAIL_PORT'] = "465"
app.config['MAIL_USERNAME'] = "ashfii.yaa22@gmail.com"
app.config['MAIL_PASSWORD'] = "nvcapyzwonrbodog"
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True


db = SQLAlchemy(app) # Instantiation of Flask-SQLAlchemy object.

class User(db.Model):
    id       = db.Column(db.Integer(), primary_key=True, nullable=False)
    email    = db.Column(db.String(32), unique=True, nullable=False)
    name     = db.Column(db.String(64), nullable=False)
    level     = db.Column(db.String(64), nullable=False)
    password = db.Column(db.String(256), nullable=False)
##########################
##### END: Database #####
########################

###########################
##### BEGIN: Sign Up #####
#########################
parser4Register = reqparse.RequestParser()
parser4Register.add_argument(
    'email', type=str, help="Email Anda", location='json', required=True)
parser4Register.add_argument(
    'name', type=str, help="Nama Anda", location='json', required=True)
parser4Register.add_argument(
    'password', type=str, help="Password", location='json', required=True)

@app.route('/register', methods=["GET", "POST"])
def regis_admin():
    if request.method == "POST":
        email = request.form["email"]
        name = request.form["name"]
        password = request.form["password"]
        re_password = request.form["re_password"]

        loguser = db.session.execute(db.select(User).filter_by(email=email)).first()

        if loguser is None:
            level = "Admin"
            register = User(email=email, name=name, password=generate_password_hash(password), level=level)
            db.session.add(register)
            db.session.commit()
            return jsonify(["Register success, Silahkan Login!"])
        elif password != re_password:
            return jsonify(["Password tidak sama!"])
        else:
            return jsonify(["Email Telah digunakan!"])

#########################
##### END: Sign Up #####
#######################

###########################
##### BEGIN: Sign In #####
#########################
SECRET_KEY      = "WhatEverYouWant"
ISSUER          = "myFlaskWebservice"
AUDIENCE_MOBILE = "myMobileApp"

parser4LogIn = reqparse.RequestParser()
parser4LogIn.add_argument('email', type=str, help='Email', location='json', required=True)
parser4LogIn.add_argument('password', type=str, help='Password', location='json', required=True)

@app.route('/login', methods=["GET", "POST"])
def flutter_login():
    if request.method == "POST":
        email = request.form["email"]
        # session['email'] = email
        password = request.form["password"]

        if not email or not password:
            return jsonify(["Masukan email dan password!"])

        user = db.session.execute(
            db.select(User).filter_by(email=email)).first()

        if not user:
            return jsonify(["Password dan email salah!"])
        else:
            user = user[0]

        if check_password_hash(user.password, password):
            email_encode = email.encode("utf-8")
            # pw_encode = password.encode("utf-8")
            base64_bytes = base64.b64encode(email_encode)
            token = base64_bytes.decode("utf-8")

            return jsonify(
                {
                    'message': f"Berhasil Login!",
                    #  'token': token,
                    'token': token
                }
            )
            # payload = {
            #     'id': user.id,
            #     'email': user.email,
            #     'aud': AUDIENCE_MOBILE,
            #     'iss': ISSUER,
            #     'iat': datetime.utcnow(),
            #     'exp': datetime.utcnow() + timedelta(hours=2)
            # }
            # token = jwt.encode(payload, SECRET_KEY)
            # print(token)

            # return jsonify(
            #     {
            #      'message': f"Success! Cek Email Token!",
            #      'token': token
            #     }
            # )
        else:
            return jsonify(["Email dan Password salah!"])



#########################
##### END: Sign In #####
#######################

#########################
##### MAIL #####
#######################

SECRET_KEY      = "WhatEverYouWant"
ISSUER          = "myFlaskWebservice"
AUDIENCE_MOBILE = "myMobileApp"

parser4Mail = reqparse.RequestParser()
parser4Mail.add_argument('email', type=str, help='Email', location='json', required=True)
parser4Mail.add_argument('password', type=str, help='Password', location='json', required=True)

@api.route('/mail')
class LogIn(Resource):
    @api.expect(parser4Mail)
    def post(self):
        # BEGIN: Get request parameters.
        args        = parser4LogIn.parse_args()
        email       = args['email']
        password    = args['password']
        # END: Get request parameters.

        if not email or not password:
            return {
                'message': 'Please fill your email and password!'
            }, 400

        # BEGIN: Check email existance.
        user = db.session.execute(
            db.select(User).filter_by(email=email)).first()

        if not user:
            return {
                'message': 'The email or password is wrong!'
            }, 400
        else:
            user = user[0] # Unpack the array.
        # END: Check email existance.

        # BEGIN: Check password hash.
        if check_password_hash(user.password, password):
            payload = {
                'user_id': user.id,
                'email': user.email,
                'aud': AUDIENCE_MOBILE, # AUDIENCE_WEB
                'iss': ISSUER,
                'iat': datetime.utcnow(),
                'exp': datetime.utcnow() + timedelta(hours = 2)
            }
            token = jwt.encode(payload, SECRET_KEY)
            subject = "Token Verification"
            msg = token

            message = Message(subject, sender="ashfii.yaa22@gmail.com", recipients=[email])
            message.body = msg
            mail.send(message)

#############################
##### END: MAIL ####
###########################

########################################################################################
###################### UBAH PASSWORD ####################################################


@app.route('/reset-password', methods=['POST'])
def reset_password():
    if request.method == "POST":
        email = request.form["email"]
    # email = request.form.get('email')
    
    # Lakukan validasi email dan generate token
    # Kirim email pengubahan password ke alamat email yang diberikan
    
    return 'Email pengubahan password telah dikirim'


##################################################################################################
############################################ END UBAH PASSWORD ######################################
#############################
##### BEGIN: Basic Auth ####
###########################
import base64
parser4Basic = reqparse.RequestParser()
parser4Basic.add_argument('Authorization', type=str,
    location='headers', required=True, 
    help='Please, read https://swagger.io/docs/specification/authentication/basic-authentication/')

@api.route('/basic-auth')
class BasicAuth(Resource):
    @api.expect(parser4Basic)
    def post(self):
        request.form        = parser4Basic.parse_request.form()
        basicAuth   = request.form['Authorization']
        # basicAuth is "Basic bWlyemEuYWxpbS5tQGdtYWlsLmNvbTp0aGlzSXNNeVBhc3N3b3Jk"
        base64Str   = basicAuth[6:] # Remove first-6 digits (remove "Basic ")
        # base64Str is "bWlyemEuYWxpbS5tQGdtYWlsLmNvbTp0aGlzSXNNeVBhc3N3b3Jk"
        base64Bytes = base64Str.encode('ascii')
        msgBytes    = base64.b64decode(base64Bytes)
        pair        = msgBytes.decode('ascii')
        # pair is mirza.alim.m@gmail.com:thisIsMyPassword
        email, password = pair.split(':')
        # email is mirza.alim.m@gmail.com, password is thisIsMyPassword
        return {'email': email, 'password': password}
###########################
##### END: Basic Auth ####
#########################

####################################
##### BEGIN: Bearer/Token Auth ####
##################################
parser4Bearer = reqparse.RequestParser()
parser4Bearer.add_argument('Authorization', type=str, 
    location='headers', required=True, 
    help='Please, read https://swagger.io/docs/specification/authentication/bearer-authentication/')

@api.route('/bearer-auth')
class BearerAuth(Resource):
    @api.expect(parser4Bearer)
    def post(self):
        request.form        = parser4Bearer.parse_request.form()
        bearerAuth  = request.form['Authorization']
        # basicAuth is "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxLCJlbWFpbCI6Im1pcnphLmFsaW0ubUBnbWFpbC5jb20iLCJhdWQiOiJteU1vYmlsZUFwcCIsImlzcyI6Im15Rmxhc2tXZWJzZXJ2aWNlIiwiaWF0IjoxNjc5NjQwOTcxLCJleHAiOjE2Nzk2NDgxNzF9.1ZxTlAT7bmkLQDgIvx0X3aWJaeUn8r6LjGDyhfrt3S8"
        jwtToken    = bearerAuth[7:] # Remove first-7 digits (remove "Bearer ")
        # jwtToken is "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxLCJlbWFpbCI6Im1pcnphLmFsaW0ubUBnbWFpbC5jb20iLCJhdWQiOiJteU1vYmlsZUFwcCIsImlzcyI6Im15Rmxhc2tXZWJzZXJ2aWNlIiwiaWF0IjoxNjc5NjQwOTcxLCJleHAiOjE2Nzk2NDgxNzF9.1ZxTlAT7bmkLQDgIvx0X3aWJaeUn8r6LjGDyhfrt3S8"
        try:
            payload = jwt.decode(
                jwtToken, 
                SECRET_KEY, 
                audience = [AUDIENCE_MOBILE], 
                issuer = ISSUER, 
                algorithms = ['HS256'], 
                options = {"require": ["aud", "iss", "iat", "exp"]}
            )
        except:
            return {
                'message' : 'Unauthorized! Token is invalid! Please, Sign in!'
            }, 401
        
        return payload, 200
##################################
##### END: Bearer/Token Auth ####
################################

@app.route('/basicToken', methods=["GET", "POST"])
def basicToken():
    if request.method == "POST":
        token = request.form['token']
        base64Bytes = token.encode('utf-8')
        msgBytes = base64.b64decode(base64Bytes)
        email = msgBytes.decode('utf-8')

        user = db.session.execute(
            db.select(User).filter_by(email=email)).first()

        if not token:
            return jsonify([f'Token Gagal!']), 400
        else:
            user = user[0]

        # if token:
        if user.level == "Admin":
            # validasi = 'Valid'
            # user.token = token
            # # user.status_validasi = validasi

            # db.session.add(user)
            # db.session.commit()

            return jsonify(["Anda sebagai administrator!"])

        # elif user.level == "User":
        #     validasi = 'Valid'
        #     user.token = token
        #     user.status_validasi = validasi

        #     db.session.add(user)
        #     db.session.commit()

        #     return jsonify(["Berhasil masuk!"])
###################################################################################        
##########################CAMERA#############################################


def generate_frames():
    while True:
        success, frame = camera.read()
        if not success:
            break
        else:
            ret, buffer = cv2.imencode('.jpg', frame)
            frame = buffer.tobytes()
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')

@app.route('/nisa')
def index():
    return render_template('index.html')

@app.route('/video_feed')
def video_feed():
    return Response(generate_frames(), mimetype='multipart/x-mixed-replace; boundary=frame')



##################################################################################
######################################END#######################################


###################################################
################## Visualisai Data ###################

# Endpoint untuk mengirim data visualisasi dari Streamlit ke Flutter
# @app.route('/visualizations', methods=['POST'])
# def send_visualizations():
#     # Ambil data visualisasi dari Streamlit (contoh: visualizations merupakan list data visualisasi)
#     visualizations = get_visualizations()

#     # Kirim data visualisasi dalam format JSON
#     return jsonify(visualizations)

# # Fungsi untuk mendapatkan data visualisasi dari Streamlit
# def get_visualizations():
#     # Kode untuk menghasilkan dan mengembalikan data visualisasi
#     return visualizations

@app.route('/Vdata')
def home():
    return render_template('Vdata.html')

##########################################################
################################# END #####################

# if __name__ == '__main__':
#     app.run(debug=True,host='192.168.56.90')


if __name__ == '__main__':
    app.run(debug=True, port=os.getenv("PORT", default=5000))
