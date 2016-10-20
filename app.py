from flask import Flask, request, flash, url_for, redirect, render_template, session, g
#from flask.ext.login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta

from flask_wtf import FlaskForm
from wtforms import Form, BooleanField, StringField, PasswordField, validators
from wtforms.validators import DataRequired, Length


app = Flask(__name__)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///clinets.sqlite3'
app.config['SECRET_KEY'] = "random string"

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
 
   def __init__(self, username, password, email):
      self.username = username
      self.password = password
      self.email = email
      self.registered_on = datetime.utcnow()
      
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


class UserForm(Form):
   username = StringField('username', validators=[DataRequired(), Length(max=255)])
   email = StringField('Email', validators=[DataRequired(), Length(max=255)])
   

@login_manager.user_loader
def load_user(id):
   try:
      return User.query.get(int(id))
   except:
      return None

@app.before_request
def before_request():
    g.user = current_user

@app.route('/register' , methods=['GET','POST'])
def register():
   if request.method == 'GET':
      return render_template('register.html')
   username = request.form['username']
   email = request.form['email']
   form = UserForm(request.form)
   registered_username = User.query.filter_by(username=username).first()
   registered_email = User.query.filter_by(email=email).first()
   

   if request.method == 'POST' and form.validate() and registered_username is None and registered_email is None:
      user = User(request.form['username'] , request.form['password'], request.form['email'])
      db.session.add(user)
      db.session.commit()
      flash('User successfully registered')
      return redirect(url_for('login'))
   flash('Registration failed...')
   return render_template('register.html', form=form)


@app.route('/login', methods=['GET','POST'])
def login():
   if request.method == 'GET':
      return render_template('login.html')
   username = request.form['username']
   password = request.form['password']
   registered_user = User.query.filter_by(username=username,password=password).first()
   if registered_user is None:
      flash('Username or Password is invalid' , 'error')
      return redirect(url_for('login'))
   login_user(registered_user)
   flash('Logged in successfully')
   return redirect(request.args.get('next') or url_for('show_all'))


@app.route('/logout')
def logout():
   user = g.user
   logout_user()
   return redirect(url_for('index')) 
   
@app.route('/')
@app.route('/index')
def index():
   user = g.user
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
