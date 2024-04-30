import requests
from flask import Flask, render_template, url_for, redirect, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'toosecretforya'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

current_user_name = ""


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    saved_cities = db.Column(default=None)


class RegisterForm(FlaskForm):
    username = StringField(validators=[
        InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Имя пользователя"})

    password = PasswordField(validators=[
        InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Пароль"})

    submit = SubmitField('Зарегестрироваться')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'Это имя пользователя уже занято.')


class LoginForm(FlaskForm):
    username = StringField(validators=[
        InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Имя пользователя"})

    password = PasswordField(validators=[
        InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Пароль"})

    submit = SubmitField('Войти')


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                global current_user_name
                current_user_name = user.username
                return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)


@app.route('/dashboard', methods=["GET", "POST"])
@login_required
def dashboard():
    global current_user_name
    user = User.query.filter_by(username=current_user_name).first()

    if user.saved_cities:
        user_cities = eval(user.saved_cities)
    else:
        user_cities = []

    new_city = request.form.get('city')
    if new_city:
        add_city(new_city)

    weather_data = []

    if user_cities:
        for city in user_cities:
            r = get_weather_data(city)

            weather = {
                'city': city,
                'temperature': r['main']['temp'],
                'description': r['weather'][0]['description'],
                'icon': r['weather'][0]['icon'],
            }

            weather_data.append(weather)

    return render_template('dashboard.html', weather_data=weather_data)


@app.route("/dashboard/add_city", methods=["POST", "GET"])
@login_required
def add_city(some_city_name):
    err_msg = ''
    new_city = request.form.get('city')

    if new_city:
        user = User.query.filter_by(username=current_user_name).first()
        user_cities_existing = user.saved_cities

        if user_cities_existing:
            user_cities = eval(user_cities_existing)
        else:
            user_cities = []

        if new_city not in user_cities:
            new_city_data = get_weather_data(new_city)

            if new_city_data['cod'] == 200:
                user_cities.append(new_city.capitalize())

                new_user_cities = f'["{'", "'.join(user_cities)}"]'

                user.saved_cities = new_user_cities
                db.session.commit()
            else:
                err_msg = 'Не могу найти город, проверьте написание!'
        else:
            err_msg = 'Город уже добавлен!'

    if err_msg:
        flash(err_msg, 'error')
    else:
        flash("Город успешно добавлен, обновите страницу!")
        return redirect(url_for("dashboard"))


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


def get_weather_data(city):
    url = (f'http://api.openweathermap.org/data/2.5/weather?q={city}'
           f'&units=metric&appid=8ba7c00b3da159a909bbd442a04fd6b5&lang=ru')
    r = requests.get(url).json()
    return r


if __name__ == "__main__":
    app.run(debug=True)
