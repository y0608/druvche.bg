import os
import secrets
from flask import Flask, render_template, url_for, flash, redirect,request
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, EqualTo,ValidationError
from flask_wtf.file import FileField, FileAllowed
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_login import login_user ,LoginManager ,UserMixin,current_user,logout_user,login_required
import folium
from folium.plugins import MarkerCluster
import base64
from datetime import datetime
import math
from PIL import Image
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask_mail import Message
from flask_mail import Mail
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

app = Flask(__name__)

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///users.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False
db=SQLAlchemy(app)
bcrypt=Bcrypt(app)
app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'

app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'druvche.bg@gmail.com'
app.config['MAIL_PASSWORD'] = '!dd123456'
mail = Mail(app)

@app.route('/')
@app.route('/home')
def home():
    m = folium.Map(
        zoom_control=False
    )
    folium.plugins.locate_control.LocateControl(auto_start=True).add_to(m)
    marker_cluster = folium.plugins.marker_cluster.MarkerCluster().add_to(m)

    locations=[]
    trees = Tree.query.all()
    for tree in trees:
        locations.append([tree.coordx,tree.coordy, tree.username,tree.data])

    for location in locations:
        encoded = base64.b64encode(open(f'static/pics/{location[3]}', 'rb').read()).decode()
        html = f'<img src="data:image;base64,{encoded}"> <h1>{location[2]}</h1>'
        iframe = folium.IFrame(html, width=200, height=200)
        popup = folium.Popup(iframe, max_width=200, max_height=200)
        folium.Marker(location[0:2], popup=popup ,icon = folium.Icon(color='lightgreen', icon='tree', prefix='fa')).add_to(marker_cluster)   
    m.save('templates/map.html')
    return render_template('home.html')

@app.route('/my_trees')
def my_trees():
    m = folium.Map(
        # location=[45.5244, -122.6699], 
        zoom_control=False
    )
    folium.plugins.locate_control.LocateControl(auto_start=True).add_to(m)
    marker_cluster = folium.plugins.marker_cluster.MarkerCluster().add_to(m)

    locations=[]
    trees = Tree.query.filter_by(username=current_user.username).all()
    for tree in trees:
        locations.append([tree.coordx,tree.coordy])
        print(tree)

    pos = folium.plugins.mouse_position.MousePosition().add_to(m)
    for location in locations:
        folium.Marker(location, popup="popup" ,icon = folium.Icon(color='lightgreen', icon='tree', prefix='fa')).add_to(marker_cluster)   
    m.save('templates/map.html')
    return render_template('my_trees.html')
    return render_template('account.html', title='Account')
    
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class RequestResetForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError('There is no account with that email. You must register first.')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')
class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Post')

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Post('{self.title}', '{self.date_posted}')"



class User(db.Model,UserMixin):
    id=db.Column("id",db.Integer,primary_key=True)
    username=db.Column("uesername",db.String(12),unique=True,nullable=False)
    email=db.Column("email",db.String(120),unique=True,nullable=False)
    image=db.Column("image",db.String(20),nullable=False,default='default.jpg')
    password=db.Column("password",db.String(60),nullable=False)
    posts = db.relationship('Post', backref='author', lazy=True)
    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.image}')"
    
class RegistrationForm(FlaskForm):
    username = StringField('Потребителско име',validators=[DataRequired(), Length(min=4, max=12)])
    email = StringField('Имейл',validators=[DataRequired(), Email()])
    password = PasswordField('Парола', validators=[DataRequired()])
    confirm_password = PasswordField('Потвърди парола',validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Регистрирай се')
    def validate_username(self,username):
        user=User.query.filter_by(username=username.data).first()
        if user!=None:
            raise ValidationError('Потребителското име е заето')
    def validate_email(self,email):
        user=User.query.filter_by(email=email.data).first()
        if user!=None:
            raise ValidationError('Имейлът е зает')

class LoginForm(FlaskForm):
    email = StringField('Имейл',validators=[DataRequired(), Email()])
    password = PasswordField('Парола', validators=[DataRequired()])
    remember = BooleanField('Запомни ме')
    submit = SubmitField('Влез')

class Tree(db.Model):
    id = db.Column("id",db.Integer, primary_key=True)
    name = db.Column("name",db.String(300), nullable=False)
    data = db.Column("data",db.Integer, nullable=False)
    coordx = db.Column("coordx",db.Float, nullable=False)
    coordy = db.Column("coordy",db.Float, nullable=False)
    username = db.Column("username", db.String(12), nullable=False)

class UpdateForm(FlaskForm):
    username = StringField('Username',validators=[DataRequired(), Length(min=4, max=12)])
    email = StringField('Email',validators=[DataRequired(), Email()])
    picture=FileField('Change Profile Picture',validators=[FileAllowed(['jpg','png'])])
    submit = SubmitField('Save Changes')
    def validate_username(self,username):
        if username.data!=current_user.username:
            user=User.query.filter_by(username=username.data).first()
            if user!=None:
                raise ValidationError('That username is taken. Choose another one')
    def validate_email(self,email):
        if email.data!=current_user.email:
            user=User.query.filter_by(email=email.data).first()
            if user!=None:
                raise ValidationError('That email is taken. Choose another one')

@app.route('/add_sapling')
def add_sapling():
    return render_template('add_sapling.html')

@app.route('/upload_sapling', methods=['POST'])
def upload():
    file = request.files['img1']
    new_img = save_pic(file)
    coordx = request.form['coordsx']
    coordy = request.form['coordsy']
    newFile = Tree(name=file.filename, data=new_img, coordx=coordx, coordy=coordy, username=current_user.username)
    db.session.add(newFile)
    db.session.commit()
    return redirect(url_for('home'))
def save_pic(picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(picture.filename)
    picture_name = random_hex + f_ext
    path = os.path.join(app.root_path, 'static/pics', picture_name)
    output_size = (100, 100)
    a = Image.open(picture)
    a.thumbnail(output_size)
    a.save(path)
    return picture_name

@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        crypt_pass=bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user=User(username=form.username.data,email=form.email.data,password=crypt_pass)
        db.session.add(user)
        db.session.commit()
        flash(f'Акаунтът беше създаден!')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('account'))
    form = LoginForm()
    if form.validate_on_submit():
        user=User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password,form.password.data):
            login_user(user,remember=form.remember.data)
            return redirect(url_for('home'))
        else:
            flash('Грешен имейл или парола.')
    return render_template('login.html', title='Login', form=form)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('login'))
def save_pic(picture):
    random_hex=secrets.token_hex(8)
    _,f_ext=os.path.splitext(picture.filename)
    picture_name=random_hex+f_ext
    path=os.path.join(app.root_path,'static/pics',picture_name)
    output_size=(100,100)
    a=Image.open(picture)
    a.thumbnail(output_size)
    a.save(path)
    return picture_name

@app.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    form=UpdateForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file=save_pic(form.picture.data)
            current_user.image=picture_file
        current_user.username=form.username.data
        current_user.email=form.email.data
        db.session.commit()
        flash('The changes are saved','success')
        redirect(url_for('account'))
    elif request.method=='GET':
        form.username.data=current_user.username
        form.email.data=current_user.email   
    image_file=url_for('static',filename='pics/'+current_user.image)
    return render_template('account.html', title='Account',image_file=image_file,form=form)

def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request',
                  sender='noreply@demo.com',
                  recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}
If you did not make this request then simply ignore this email and no changes will be made.
'''
    mail.send(msg)

@app.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash('An email has been sent with instructions to reset your password.', 'info')
        return redirect(url_for('login'))
    return render_template('reset_request.html', title='Reset Password', form=form)

@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash('Your password has been updated! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', title='Reset Password', form=form)
    
class U:
    def __init__(self,score,username):
        self.__score=score
        self.__username=username

    def get_score(self):
        return self.__score

    def get_username(self):
        return self.__username

def func(e):
    return e.get_score()

def sort_scoreboard():
    usernames=User.query.all()
    users=[]
    curr=U(0,"error")
    for x in range(0,len(usernames)):
        if usernames[x]==current_user.username:
            curr=U(len(Tree.query.filter(Tree.username==usernames[x].username).all()),usernames[x].username)
            users.append(curr)
        else:
            users.append(U(len(Tree.query.filter(Tree.username==usernames[x].username).all()),usernames[x].username))
    users.sort(reverse=True, key=func)
    if curr in users:
        users.index(curr)
    return users

@app.route("/scoreboard")
def scoreboard():
    if current_user.is_authenticated:
        users = sort_scoreboard()
        headings = ["Име", "Дръвчета"]
        data = []
        if len(users)>20:
            for i in range(0,20):
                a = []
                a.append(users[i].get_username())
                a.append(users[i].get_score())
                data.append(a)
        else:
            for i in range(0,len(users)):
                a = []
                a.append(users[i].get_username())
                a.append(users[i].get_score())
                data.append(a)
        return render_template('scoreboard.html', headings=headings, data=data)
    return redirect(url_for('login'))

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)