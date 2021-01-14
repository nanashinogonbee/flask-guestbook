from flask import Flask, url_for, render_template, request, flash, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import json
import requests as rq


app = Flask(__name__)
APP_NAME = 'chat'
data = None
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///base.db'
app.config['SECRET_KEY'] = 'fdgdfgdfggf786hfg6hfg6h7f'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'index'
login_manager.login_message = 'Авторизуйтесь для доступа к гостевой книге'
login_manager.login_message_category = 'error'
print(login_manager.__dict__)


class User(UserMixin, db.Model):
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(80), unique=True, nullable=False)
	password = db.Column(db.String(80), nullable=False)
	is_admin = db.Column(db.BOOLEAN, default=False)

	def __init__(self, username, password):
		self.username = username
		self.password = password

	def get(self):
		return tuple(self.id, self.username, self.password)


class Message(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	user_name = db.Column(db.String(80), nullable=False)
	message_text = db.Column(db.String(120), nullable=False)
	is_hidden = db.Column(db.BOOLEAN, default=False)

	def __init__(self, username, message_text):
		self.user_name = username
		self.message_text = message_text


db.create_all()


def update_messages_buffer() -> list:
	return Message.query.all()


messages = update_messages_buffer()


@login_manager.user_loader
def load_user(user_id):
	user = User.query.filter_by(id=user_id).first()
	return user


@app.route('/',  methods=['GET', 'POST'])
def index():
	if current_user.is_authenticated:
		return redirect(url_for('main_page'))
	if request.method == "POST":
		user = User.query.filter_by(username=request.form['username']).first()
		if user and check_password_hash(user.password, request.form['psw']):
			login_user(user)
			if user.is_admin:
				flash(
                                    'Вы успешно зашли в запись администратора', 
                                    'success'
                                    )
				return redirect(url_for('admin'))
			else:
				return redirect(url_for('main_page'))
		else:
			flash(
                            'Такого пользователя нет или неверно введён пароль!',
                            category='error'
                            )
			return redirect(url_for('index'))
	else:
		return render_template('login.html', appname=APP_NAME)


@app.route('/admin',  methods=["POST", "GET"])
@login_required
def admin():
	if current_user.is_admin and current_user.is_authenticated:
		return render_template('admin.html', appname=APP_NAME, messages=messages)
	elif current_user.is_authenticated:
		flash('Вы не являетесь администратором!', 'error')
		return redirect(url_for('index'))


@app.route('/add/message', methods=['POST'])
def add_message():
	global messages
	msg = Message(current_user.username, request.form['msgtxt'])
	db.session.add(msg)
	db.session.commit()
	messages = update_messages_buffer()
	return redirect(url_for('main_page'))


@app.route('/edit/message', methods=['POST'])
def edit_message():
	try:
		msg = Message.query.filter_by(
                    id=int(request.form['msg_id'])
                    ).first()
		if current_user.username == msg.user_name:
			global messages
			msg.message_text = request.form['ed_txt']
			db.session.commit()
			messages = update_messages_buffer()
			flash('Сообщение успешно изменено!', 'success')
		else:
			flash('Вы не можете редактировать сообщения других пользователей!', 'error')
	except AttributeError as e:
		flash('Сообщения с таким id не существует!', 'error')
	return redirect(url_for('main_page'))


@app.route('/main_page')
@login_required
def main_page():
	if current_user.is_admin:
		return redirect(url_for('admin'))
	return render_template(
            'index.html',
            appname=APP_NAME,
            messages=messages
            )


@app.route('/delete_msg/<msg_id>', methods=['POST'])
def delete_msg(msg_id):
	global messages
	msg = Message.query.filter_by(id=msg_id).first()
	db.session.delete(msg)
	db.session.commit()
	messages = update_messages_buffer()
	return redirect(url_for('admin'))


@app.route('/hidden_msg', methods=['POST'])
def hidden_msg():
	global messages
	msg = Message.query.filter_by(id=int(request.json['recordId'])).first()
	msg.is_hidden = request.json['state']
	db.session.commit()
	messages = update_messages_buffer()
	return json.dumps(
            {'success': True}
            ), 200, {'ContentType': 'application/json'}


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
	logout_user()
	flash('Вы вышли из аккаунта', 'success')
	return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
	if request.method == 'POST':
		if request.form['psw'] == request.form['psw2']:
			user = User(
                            request.form['name'],
                            generate_password_hash(request.form['psw'])
                            )
			db.session.add(user)
			db.session.commit()
			flash(
                            'Пользователь {} успешно зарегистрирован!'.format(request.form['name']),
                            category='success'
                            )
			return redirect(url_for('index'))
		else:
			flash('Ваши пароли не совпадают', category='error')

	return render_template('register.html', title='Регистрация')


if __name__ == '__main__':
	app.run()

