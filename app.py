from datetime import datetime
from flask import Flask, render_template, url_for, redirect, request
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, PasswordField, TextAreaField, IntegerField, SubmitField
from wtforms.validators import DataRequired, Email


app = Flask(__name__)
app.config["SECRET_KEY"] = "mysecretkey"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite3"

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

db = SQLAlchemy(app)


####### login manager ################


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

######### Forms ######################

class AddForm(FlaskForm):

    title = StringField('Title:', validators=[DataRequired()])
    company = StringField('Company:', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    amount = IntegerField('Amount:', validators=[DataRequired()])
    level = SelectField(u'Choose level', choices=[('Manager'), ('Senior'), ('Junior'), ('Entry'), ('Intern')])
    submit = SubmitField('Submit opportunity')


class LoginForm(FlaskForm):

    email = StringField('Email:', validators=[Email()])
    password = PasswordField('Password:', validators=[DataRequired()])
    submit = SubmitField('Log in')


class SignUpForm(FlaskForm):
    username = StringField('Username:', validators=[DataRequired()])
    email = StringField('Email:', validators=[Email()])
    password = PasswordField('Password:', validators=[DataRequired()])
    submit = SubmitField('Sign up')

######################################

############## Database models #######

class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(50), nullable=False)
    opportunities = db.relationship('Opportunity', backref='author', lazy=True)
    discoveries = db.relationship('Discovery', backref='author', lazy=True)

    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password = password

    def json(self):
        opportunities = [opportunity.json() for opportunity in self.opportunities]
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'opportunities': opportunities
        }


class Opportunity(db.Model):
    __tablename__ = 'opportunities'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50), nullable=False)
    company = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(255), nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    level = db.Column(db.String(50), nullable=False)
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    discoveries = db.relationship('Discovery', backref='opportunity', lazy=True)

    def __init__(self, title, company, description, amount, level, user_id):
        self.title = title
        self.company = company
        self.description = description
        self.amount = amount
        self.level = level
        self.user_id = user_id


    def json(self):
        discoveries = [discovery.json() for discovery in self.discoveries]
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'amount': self.amount,
            'level': self.level,
            'discoveries': len(discoveries),
            'author': self.author.username,
            'date_posted': self.date_posted
        }


class Discovery(db.Model):
    __tablename__ = 'discoveries'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    opportunity_id = db.Column(db.Integer, db.ForeignKey('opportunities.id'), nullable=False)

    def __init__(self, user_id, opportunity_id):
        self.user_id = user_id
        self.opportunity_id = opportunity_id

    def json(self):
        return {'user_id': self.user_id, 'opportunity_id': self.opportunity_id}
######################################


@app.route('/')
def index():

    opportunities_list = Opportunity.query.all()
    n_opportunities = [opportunity.json() for opportunity in opportunities_list]
    opportunities = n_opportunities[::-1]

    return render_template('index.html', opportunities=opportunities)


@app.route('/add', methods=['GET', 'POST'])
@login_required
def add():
    form = AddForm()

    if form.validate_on_submit():

        title = form.title.data
        company = form.company.data
        description = form.description.data
        amount = form.amount.data
        level = form.level.data

        opportunity = Opportunity(title, company, description, amount, level, user_id=current_user.id)
        db.session.add(opportunity)
        db.session.commit()

        return redirect(url_for('index'))

    return render_template('add.html', form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignUpForm()

    if form.validate_on_submit():

        username = form.username.data
        email = form.email.data
        password = generate_password_hash(form.password.data)

        user = User(username, email, password)
        db.session.add(user)
        db.session.commit()

        return redirect(url_for('login'))

    return render_template('signup.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and check_password_hash(user.password, form.password.data):

            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))

    return render_template('login.html', form=form)

@app.route('/opportunity/<int:opportunity_id>')
@login_required
def opportunity(opportunity_id):

    discovery = Discovery(current_user.id, opportunity_id)
    db.session.add(discovery)
    db.session.commit()

    opportunity_q = Opportunity.query.filter_by(id=opportunity_id).first()
    opportunity = opportunity_q.json()

    return render_template('opportunity.html', opportunity=opportunity)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
