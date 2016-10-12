#!/usr/bin/env python3

from flask import Flask, request, flash, url_for, redirect, render_template
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///clinets.sqlite3'
app.config['SECRET_KEY'] = "random string"

db = SQLAlchemy(app)

class feature_request(db.Model):
   id = db.Column('client_id', db.Integer, primary_key = True)
   title        = db.Column(db.String(100))
   description  = db.Column(db.String(50))
   client       = db.Column(db.String(200)) 
   priority     = db.Column(db.Integer(10))
   targetdate   = db.Column(db.String(10))
   productarea  = db.Column(db.String(10))

   def __init__(self, title, description, client, priority, targetdate, productarea):
      self.title       = title
      self.description = description
      self.client      = client
      self.priority    = priority
      self.targetdate  = targetdate
      self.productarea = productarea
   
@app.route('/')
def show_all():
   return render_template('show_all.html', feature_request = feature_request.query.all() )

@app.route('/new', methods = ['GET', 'POST'])
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
