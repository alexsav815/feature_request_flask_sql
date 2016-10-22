from flask import Flask, request, flash, url_for, redirect, render_template, session, g, make_response
#from flask.ext.login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta

from flask_wtf import FlaskForm
from wtforms import Form, BooleanField, StringField, PasswordField, validators
from wtforms.validators import DataRequired, Length, Email

from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message

app = Flask(__name__)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///clinets.sqlite3'
app.config['SECRET_KEY'] = "Sm9obiBTYqwfGSDTRNrtgercHJFlja3MgYXNz"
app.config['SECURITY_PASSWORD_SALT'] = 'email-confirm-key'
app.config['MAIL_DEFAULT_SENDER'] = 'feature_request'
app.config.update(
    #EMAIL SETTINGS
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=465,
    MAIL_USE_SSL=True,
    MAIL_USERNAME = 'featurerequestflask',
    MAIL_PASSWORD = 'featurerequest4$'
)
mail = Mail(app)

#app.config['SESSION_COOKIE_SECURE'] = True


db = SQLAlchemy(app)

class feature_request(db.Model):
   id = db.Column('client_id', db.Integer, primary_key = True)
   title        = db.Column(db.String(100))
   description  = db.Column(db.String(50))
   client       = db.Column(db.String(200)) 
   #priority     = db.Column(db.Integer(10))
   priority     = db.Column(db.Integer)
   targetdate   = db.Column(db.String(10))
   productarea  = db.Column(db.String(10))

   def __init__(self, title, description, client, priority, targetdate, productarea):
      self.title       = title
      self.description = description
      self.client      = client
      self.priority    = priority
      self.targetdate  = targetdate
      self.productarea = productarea


class User(db.Model):
   __tablename__ = "User"
   id = db.Column('user_id', db.Integer, primary_key=True)
   username = db.Column('username', db.String(20), nullable=False, unique=True, index=True)
   password = db.Column('password', db.String(10), nullable=False)
   email = db.Column('email', db.String(50), unique=True, nullable=False, index=True)
   registered_on = db.Column('registered_on', db.DateTime())
   confirmed = db.Column('confirmed', db.Boolean(), nullable=False, default=False)
   confirmed_on = db.Column('confirmed_on', db.DateTime(), nullable=True)

   def __init__(self, username, password, email, confirmed, confirmed_on=None):
      self.username = username
      self.password = password
      self.email = email
      self.registered_on = datetime.utcnow()
      self.confirmed = confirmed
      self.confirmed_on = confirmed_on

   def is_authenticated(self):
      return True
      
   def is_active(self):
      return True
 
   def is_anonymous(self):
      return False
 
   def get_id(self):
      try:
         return unicode(self.id)  # python 2
      except NameError:
         return str(self.id)  # python 3
       
   def __repr__(self):
      return '<User %r>' % (self.username)


def send_email(to, subject, template):
   msg = Message(
      subject,
      recipients=[to],
      html=template,
      sender=app.config['MAIL_DEFAULT_SENDER']
   )
   mail.send(msg)
   

def generate_confirmation_token(email):
   serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
   return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])


def confirm_token(token, expiration=86400):
   serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
   try:
      email = serializer.loads(
         token,
         salt=app.config['SECURITY_PASSWORD_SALT'],
         max_age=expiration
      )
   except:
      return False
   return email


class UserForm(Form):
   username = StringField('username', validators=[DataRequired(), Length(max=255)])
   email = StringField('email', validators=[DataRequired(), Email(), Length(max=255)])

class UserPasswordForm(Form):
   username = StringField('username', validators=[DataRequired(), Length(max=255)])
   password = PasswordField('password', validators=[DataRequired()])
     
#login_manager.session_protection = "strong"

@login_manager.user_loader
def load_user(id):
   try:
      return User.query.get(int(id))
   except:
      return None

@app.before_request
def before_request():
   g.user = current_user

def regLog(message, category):
   flash(message, category)
   return render_template("register.html")

def logLog(message, category):
   flash(message, category)
   return render_template("login.html")

def confirmLog(message, category):
   flash(message, category)
   return render_template("index.html")


@app.route('/register' , methods=['GET','POST'])
def register():
   if request.method == 'GET':
      return render_template('register.html')
   username = request.form['username']
   password = request.form['password']
   password1 = request.form['password1']
   if password != password1:
      return regLog("<strong>Error!</strong> Passwords did not match. Please enter passwords again...", 'danger')
   email = request.form['email']
   email1 = request.form['email1']
   if email != email1:
      return regLog("<strong>Error!</strong> Email addresses did not match. Please enter e-mailss again...", 'danger')
   form = UserForm(request.form)
   registered_username = User.query.filter_by(username=username).first()
   registered_email = User.query.filter_by(email=email1).first()
   if registered_username is not None:
      return regLog("<strong>Error!</strong> Username is already used. Please chose different username...",'danger')
   if registered_email is not None:
      return regLog("<strong>Error!</strong> E-mail entered is already used. Please enter different e-mail...",'danger')

   if request.method == 'POST' and form.validate():
      user = User(request.form['username'] , request.form['password1'], request.form['email1'], confirmed=False)
      db.session.add(user)
      db.session.commit()
      
      token = generate_confirmation_token(user.email)
      confirm_url = url_for('confirm_email', token=token, _external=True)
      html = render_template('email/activate.html', confirm_url=confirm_url)
      subject = "Please confirm your email"
      send_email(user.email, subject, html)

      return regLog("User successfully registered! A confirmation link has been sent via email. <br> You may now <a href = \"login\"> Login </a>",'success')
      #return redirect(url_for('login'))
      ###login_user(user)
      #flash('A confirmation email has been sent via email.', 'success')
      #return redirect(url_for('unconfirmed'))

   return regLog('<strong>Error!</strong> Registration failed...', 'danger')
   return render_template('register.html', form=form)


@app.route('/confirm/<token>')
#@login_required
def confirm_email(token):
   try:
      email = confirm_token(token)
   except:
      return confirmLog('The confirmation link is invalid or has expired.', 'danger')
      abort(404)

   user = User.query.filter_by(email=email).first_or_404()
   if user.confirmed:
       return confirmLog('Account already confirmed.', 'success')
   else:
      user.confirmed = True
      user.confirmed_on = datetime.utcnow()
      db.session.add(user)
      db.session.commit()
      login_user(user)
      return confirmLog('You have confirmed your account. Thanks!', 'success')
   #return redirect(url_for('index'))


@app.route('/unconfirmed')
@login_required
def unconfirmed():
    if current_user.confirmed:
        return redirect('index')
    #return unconfirmedLog('Please confirm your account!', 'warning')
    return render_template('unconfirmed.html')


@app.route('/resend')
@login_required
def resend_confirmation():
    token = generate_confirmation_token(current_user.email)
    confirm_url = url_for('confirm_email', token=token, _external=True)
    html = render_template('email/activate.html', confirm_url=confirm_url)
    subject = "Please confirm your email"
    send_email(current_user.email, subject, html)
    flash('A new confirmation email has been sent', 'success')
    return redirect(url_for('unconfirmed'))


@app.route('/login', methods=['GET','POST'])
def login():
   if request.method == 'GET':
      return render_template('login.html')
   username = request.form['username']
   password = request.form['password']
   registered_user = User.query.filter_by(username=username,password=password).first()
   if registered_user is None:
      return logLog('<strong>Error!</strong> Username or Password is invalid', 'danger')
      return redirect(url_for('login'))
   #form = UserPasswordForm()
   #if form.validate():
   login_user(registered_user)
   #return logLog("Logged in successfully. You may now  <a href = \"show_all\"> proceed </a>", 'success')
   if current_user.confirmed:
      return redirect(request.args.get('next') or url_for('show_all'))
   #flash('Please confirm your account!', 'warning')
   return redirect(url_for('unconfirmed'))

   #return redirect(request.args.get('next') or url_for('show_all'))
   
@app.route('/logout')
def logout():
   user = g.user
   logout_user()
   return redirect(url_for('index')) 
   
@app.route('/')
@app.route('/index')
def index():
   user = g.user
   #resp = make_response(render_template('index.html', user=user))
   #resp.set_cookie('PHPSESSID', '')
   #return resp
   return render_template('index.html', user=user)

@app.route('/show_all')
@login_required
def show_all():
   return render_template('show_all.html', feature_request = feature_request.query.all() )

@app.route('/new', methods = ['GET', 'POST'])
@login_required
def new():
   if request.method == 'POST':
      #print (request.form['title'])
      if not request.form['title'] or not request.form['description'] or not request.form['targetdate']:
         flash('Please enter all the fields', 'error')
      else:
         current_request = feature_request(request.form['title'], request.form['description'], request.form['client'], request.form['priority'], request.form['targetdate'], request.form['productarea'])
         
         #client_current = db.session.query(feature_request).filter(feature_request.client==request.form['client'], feature_request.priority >= request.form['priority'] ).all()
         #print ("out: ", client_current[-1].priority)
         #print ("out: ", len(client_current))
         
         entry_check = db.session.query(feature_request).filter(feature_request.client == request.form['client'], feature_request.priority == request.form['priority']).all()
         
         if (len(entry_check)):
            db.session.query(feature_request).filter(feature_request.client == request.form['client']).filter(feature_request.priority >= int(request.form['priority'])).update({'priority': feature_request.priority + 1}, synchronize_session='evaluate')

         db.session.add(current_request)
         db.session.commit()
         flash('Request entry has been successfully added to database...')
         return redirect(url_for('show_all'))
   return render_template('new.html')

if __name__ == '__main__':
   db.create_all()
   app.run(debug = True, host='0.0.0.0')
