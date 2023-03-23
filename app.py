import csv

import json
import os
import secrets
import string
from datetime import datetime

import pandas as pd
from flask import (Flask, flash, jsonify, redirect, render_template, request,
                   session, url_for)
from flask_bcrypt import Bcrypt
from flask_change_password import (ChangePassword, ChangePasswordForm,
                                   SetPasswordForm)
from flask_login import (LoginManager, UserMixin, current_user, login_required,
                         login_user, logout_user)
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm, Form
from werkzeug.utils import secure_filename
from wtforms import (BooleanField, PasswordField, SelectField,
                     SelectMultipleField, StringField, SubmitField,
                     TextAreaField)
from wtforms.validators import InputRequired, Length, ValidationError,DataRequired
from flask_change_password import ChangePassword, ChangePasswordForm, SetPasswordForm



# utilisation du FLASK_LOGIN: https://flask-login.readthedocs.io/en/latest/
# creation de la base de donnees LOCALE avec SQLALCHEMY: https://flask-sqlalchemy.palletsprojects.com/en/2.x/quickstart/
# la difference entre SQLALCHEMY et SQLITE3: SQLAlchemy est une bibliothèque de mappage objet-relationnel pour Python qui
# permet de travailler avec des bases de données en utilisant des classes Python plutôt que des requêtes SQL brutes. SQL,
# ou Structured Query Language, est un langage de programmation utilisé pour communiquer avec des bases de données relationnelles,
# comme MySQL, PostgreSQL et SQLite. SQLAlchemy permet de générer automatiquement des requêtes SQL à partir de code Python,
# tandis que SQL est utilisé pour écrire manuellement des requêtes pour interagir avec des bases de données.


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'thisisasecretkey'
socketio = SocketIO(app)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.secret_key = os.urandom(20)
flask_change_password = ChangePassword(min_password_length=10, rules=dict(long_password_override=2))
flask_change_password.init_app(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

current_exam = []

@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(id=int(user_id)).first()


class User(db.Model, UserMixin):  # table base de données
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    first_name = db.Column(db.String(150), nullable=False)
    last_name = db.Column(db.String(150), nullable=False)
    password = db.Column(db.Integer, nullable=False)
    type_user = db.Column(db.String(255), nullable=False)


class Question(db.Model, UserMixin):  # table base de données
    id = db.Column(db.Integer, primary_key=True)
    id_user = db.Column(db.Integer, db.ForeignKey(User.id), nullable=False)
    question = db.Column(db.String(255), nullable=False)
    answers = db.Column(db.String(255), nullable=False)
    tags = db.Column(db.String(255), nullable=False)

class Exam(db.Model, UserMixin):  # table base de données
    id = db.Column(db.Integer, primary_key=True)
    id_user = db.Column(db.Integer, db.ForeignKey(User.id), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    questions = db.Column(db.String(255), nullable=False)
    identifier = db.Column(db.String(255), nullable=False)

# utilisation de flask login pour la connexion et la déconnexion d'un utilisateur
# ICI pour plus d'informations : https://youtu.be/71EU8gnZqZQ


class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)],
                           render_kw={"placeholder": "Pseudonyme", "id": "username"})
    firstname = StringField(validators=[InputRequired(), Length(min=4, max=150)],
                            render_kw={"placeholder": "Nom", "id": "firstname"})
    lastname = StringField(validators=[InputRequired(), Length(min=4, max=150)],
                           render_kw={"placeholder": "Prénom", "id": "lastname"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)],
                             render_kw={"placeholder": "Mot de passe", "id": "password"})
    select_type_user = SelectField('Type d\'utilisateur', choices=[('teacher', 'Professeur'), ('student', 'Etudiant')],
                                   validators=[InputRequired()], render_kw={"id": "usertype"})

    submit = SubmitField('Register')

# fonction pour verifier si le nom d'utilisateur existe deja dans la base de donnees ou non (pour l'inscription)

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            return True
        return False


# classe pour le formulaire de creation de question
class QuestionForm(FlaskForm):
    question = TextAreaField('Question', validators=[InputRequired()],
                             render_kw={"rows": "4", "id": "question", "class": "form-control"})
    answer1 = StringField('Réponse 1', validators=[InputRequired()],
                          render_kw={"id": "answer1", "class": "form-control"})
    answer2 = StringField('Réponse 2', validators=[InputRequired()],
                          render_kw={"id": "answer2", "class": "form-control"})
    answer3 = StringField('Réponse 3', validators=[InputRequired()],
                          render_kw={"id": "answer3", "class": "form-control"})
    answer4 = StringField('Réponse 4', validators=[InputRequired()],
                          render_kw={"id": "answer4", "class": "form-control"})
    correct1 = BooleanField('Réponse correcte', default=False, render_kw={"class": "form-check-input"})
    correct2 = BooleanField('Réponse correcte', default=False, render_kw={"class": "form-check-input"})
    correct3 = BooleanField('Réponse correcte', default=False, render_kw={"class": "form-check-input"})
    correct4 = BooleanField('Réponse correcte', default=False, render_kw={"class": "form-check-input"})

    tags = SelectMultipleField('Tags', choices=[], validators=[InputRequired()],
                               render_kw={"id": "tags", "class": "form-control"})

    submit = SubmitField('Créer la question', render_kw={"class": "btn btn-success"})


# class login pour la connexion
class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)],
                           render_kw={"placeholder": "Nom d'utilisateur", "id": "username"})

    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)],
                             render_kw={"placeholder": "Mot de passe", "id": "password"})

    submit = SubmitField('LOGIN', render_kw={"id": "submit"})


@app.route('/')
@login_required
# route pour aller a la page d'accueil
def accueil():
    return render_template('accueil.html', user=current_user)


# route pour aller a la page de connexion (login) et  verifier si le nom d'utilisateur
# et le mot de passe sont corrects,  si oui, on va a la page d'accueil
@app.route('/accueil2', methods=['GET', 'POST'])
def accueil2():
    return render_template('accueil2.html', user=current_user)

@app.route('/next', methods=['GET'])
def nextPage():
    return redirect(url_for('accueil2'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('accueil'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                if current_user.type_user == 'teacher':
                    return redirect(url_for('accueil'))
                else:
                    return redirect(url_for('etudiant'))
    return render_template('login.html', form=form)
@app.route('/etudiant ', methods=['GET', 'POST'])
def etudiant():
    return render_template('etudiant.html', user=current_user)




# route pour aller a la page de deconnexion (logout) et  deconnecter l'utilisateur
@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))
@app.route('/next', methods=['GET', 'POST'])
def next():
    return redirect(url_for('accueil2'))
@app.route('/back', methods=['GET', 'POST'])
def back():
    return redirect(url_for('accueil'))


# route pour aller a la page d'inscription (register)
@app.route('/register', methods=['GET', 'POST'])
def register():
    # si l'utilisateur est connecté on le redirige vers la page dashboard
    if current_user.is_authenticated:
        return redirect(url_for('accueil'))
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password, first_name=form.firstname.data,
                        last_name=form.lastname.data, type_user=form.select_type_user.data)
        try:
            if form.validate_username(form.username):
                return render_template('register.html', form=form, error="Pseudunyme déjà utilisé")
            db.session.add(new_user)
            db.session.commit()
        except Exception as e:
            print(e)
            return "Il y a eu un problème lors de l'inscription"
        return redirect(url_for('login'))

    return render_template('register.html', form=form, error="")


# ----------------------------------------------------------------------------------------------------------------------------#

# partie creation de question
def validate_question(question):
    existing_question = Question.query.filter_by(
        question=question).first()
    if existing_question:
        return True
    return False


# fonction pour les reponses des questions
def validate_question_answers(i, q, answers, tags):
    existing = Question.query.filter(Question.question == q, Question.id == i, Question.answers == answers,
                                     Question.tags == tags).first()
    if existing:
        return True
    return False


@app.route("/create_question", methods=["GET", "POST"])  # Chemin de la page de création de question
@login_required
def create_question():  # Page de création de question
    if request.method == 'POST':
        form = json.loads(request.data)
        answers = []
        for i in range(1, 5):
            answers.append(
                {"reponse": form["answers"][f"answer{i}"], "correcte": str(form["correct"][f"correct{i}"]).lower()})
        new_question = Question(question=form["question"], id_user=current_user.id, answers=str(answers),
                                tags=str(form["tags"]))
        try:
            if validate_question(form["question"]):
                return jsonify({'success': False, 'error': 'Question déjà existante !'})
            db.session.add(new_question)
            db.session.commit()
            # return redirect(url_for('personal_questions'))
            # send json return data to client
            return jsonify({'success': True, 'message': 'Question créee avec succès !'})
        except Exception as e:
            print(e, 'error')
            return "Il y a eu un problème lors de l'ajout de la question"
    return render_template("create_question.html", error="")


# route pour aller a la page de modification de question
@app.route("/modify_question/<int:question_id>", methods=["GET", "POST"])
@login_required
def modify_question(question_id):
    question = Question.query.filter_by(id=question_id).first()
    if question is None:
        return f"La question dont l'id {question_id} n'existe pas", 404
    elif question.id_user != current_user.id:  # Si l'utilisateur n'est pas le propriétaire de la question, il ne pourra pas la modifier
        return f"Vous n'avez pas les droits pour modifier cette question", 403
    if request.method == 'POST':
        form = json.loads(request.data)

        answers = []
        for i in range(1, 5):
            answers.append(
                {"reponse": form["answers"][f"answer{i}"], "correcte": str(form["correct"][f"correct{i}"]).lower()})

        if validate_question_answers(question_id, form["question"], str(answers), str(form["tags"])):
            return jsonify({'success': False, 'error': 'Question déjà existante !'})

        question.question = form["question"]
        question.answers = str(answers)
        question.tags = str(form["tags"])

        try:
            db.session.commit()
            return jsonify({'success': True, 'message': 'Question modifiée avec succès !'})
        except Exception as e:  # Si il y a une erreur lors de la modification de la question
            print(e)
            return "Il y a eu un problème lors de la modification de la question"
    else:
        data = {
            "question": question.question,
            "answers": json.loads(question.answers.replace("'", '"')),
            "tags": json.loads(question.tags.replace("'", '"'))
        }
        return render_template("update_question.html", form=data, question_id=question_id)


@app.route("/my_questions", methods=["GET", "POST"])  # Chemin de la page de création de question
@login_required
def personal_questions():  # Page d'affichage des questions
    questions = Question.query.filter_by(id_user=current_user.id).all()
    qanda = []  # qanda = question and answers
    for question in questions:
        tags = json.loads(question.tags.replace("'", '"'))
        answers = json.loads(question.answers.replace("'", '"'))
        qanda.append(
            {'id': question.id, 'question': question.question, 'answers': [item["reponse"] for item in answers],
             'correct_answers': [item["reponse"] for item in answers if item["correcte"] == "true"], 'tags': tags})

    return render_template("my_questions.html", questions=qanda, user=current_user)


@app.route("/questions", methods=["GET"])  # Chemin de la page de création de question
@login_required
def all_questions():  # Page d'affichage des questions
    questions = Question.query.all()
    qanda = []
    for question in questions:
        answers = json.loads(question.answers.replace("'", '"'))
        qanda.append(
            {'id': question.id, 'question': question.question, 'answers': [item["reponse"] for item in answers],
             'correct_answers': [item["reponse"] for item in answers if item["correcte"] == "true"]})

    return render_template("all_questions.html", questions=qanda)


@app.route('/delete/<int:question_id>', methods=['DELETE'])  # Chemin de la page de supression de question
@login_required
def delete_question(question_id):  # Fonction de suppression de question
    question = Question.query.get(question_id)
    if question:
        if question.id_user != current_user.id:
            return jsonify({'message': "Vous n'avez pas les droits pour supprimer cette question"}), 403
        db.session.delete(question)
        db.session.commit()
        return jsonify({'message': 'La question a été supprimé', 'status': 200}), 200
    else:
        return jsonify({'message': f"La question dont l'id {question_id} n'existe pas dans la base de données",
                        'status': 404}), 404


# fonction qui recupere les bonnes reponses, recupere le tableau du dictionnaire elle parcoure la liste, si la reponse est true
# elle affiche que celles avec true
def getCorrectAnswers(answers):
    correct_answers = []
    for answer in answers:
        if answer["correcte"] == "true":
            correct_answers.append(answer["reponse"])
    return correct_answers


def getAnswers(answers):
    all_answers = []
    for answer in answers:
        all_answers.append(answer["reponse"])
    return all_answers


@app.route('/accueilEtudiant')
def accueilEtudiant():
    return render_template('accueilEtudiant.html')

@app.route('/dashbordEtudiant',methods=['GET', 'POST'])
@login_required
def dashbordEtudiant():
    return render_template('dashbordEtudiant.html')


#csv part
ALLOWED_EXTENSIONS = set(['csv'])
def allowed_file(filename):# the filename contains the csv extension
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
@app.route('/upload', methods=['GET','POST'])
def upload_file():
    if request.method == 'POST':
        file=request.files['file']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            new_filename= f'{filename.split(".")[0]}_{str(datetime.now())}.csv'
            file.save(os.path.join('input', new_filename))
        return redirect(url_for('upload_file'))
    return render_template('upload.html')

with open ('input/etudiant.csv') as csvfile:
    reader = csv.DictReader(csvfile)
    for row in reader:
        etudiant = User(username=row['username'],first_name=row['firstname'],lastname=row['lastname'] , password=row['password'], select_type_user=row['select_type_user'])
        db.session.add(etudiant)
    db.session.commit()


#partie de mahmoud
@app.route('/loginEtudiant',methods=['GET', 'POST'])
def loginEtudiant():
    form = LoginForm()
    if form.validate_on_submit():
        user=User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password,form.password.data):
                login_user(user)
                return redirect(url_for('dashbordEtudiant'))
    return render_template('loginEtudiant.html',form=form)


def logoutEtudiant_user():
    pass


@app.route('/logoutEtudiant', methods=['GET', 'POST'])
@login_required
def logoutEtudiant():
    logout_user()
    return redirect(url_for('loginEtudiant'))

@app.route('/registerEtudiant', methods=['GET', 'POST'])
def registerEtudiant():
    # si l'utilisateur est connecté on le redirige vers la page dashboard
    if current_user.is_authenticated:
        return redirect(url_for('accueilEtudiant'))
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password, first_name=form.firstname.data,
                        last_name=form.lastname.data)
        try:
            if form.validate_username(form.username):
                return render_template('registerEtudiant.html', form=form, error="Pseudunyme déjà utilisé")
            db.session.add(new_user)
            db.session.commit()
        except Exception as e:
            print(e)
            return "Il y a eu un problème lors de l'inscription"
        return redirect(url_for('login'))

    return render_template('registerEtudiant.html', form=form, error="")

@app.route('/ChangePassword', methods=["GET", "POST"])
def ChangePassword():
    if request.method == "POST":
        username = request.form['username']
        newPassword = request.form['newpassword']
        user = User.query.filter_by(username=username).first()
        if user:
            user.password = newPassword
            db.session.commit()
            msg = "Changed successfully"
            alert('Changed successfully.', 'success')
            return render_template("ChangePassword.html", success=msg)
        else:
            error = "Username not found"
            return render_template("ChangePassword.html", error=error)
    return render_template("ChangePassword.html")


@app.route('/examCode', methods=['POST'])
def examCode():
    exam_code = request.form['exam_code']
    return render_template('examCode.html', exam_code=exam_code)



@login_required
@app.route('/upload_users', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        file = request.files['file']
        if file:
            # Read the CSV file
            reader = csv.DictReader(file.stream.read().decode("utf-8").splitlines(), delimiter=';')
            errors = []
            for row in reader:
                # Add the user to the database
                new_user = User(username=row['username'], password=bcrypt.generate_password_hash(row['password']),
                                first_name=row["firstname"],
                                last_name=row["lastname"], type_user=row["type_user"])
                try:
                    db.session.add(new_user)
                    db.session.commit()
                except Exception as e:
                    print(e)
                    errors.append(row)
            errtext = f"Il y a eu des erreurs lors du chargement des utilisateurs suivants\n {errors}" if len(errors) > 0 else ''
            return jsonify({'success': True, 'message': f"Fichier importé avec succès !\n{errtext}"})
    # Render an HTML form that allows the user to select a CSV file
    return render_template('upload.html')


# partie de mahmoud
@app.route('/loginEtudiant', methods=['GET', 'POST'])
def loginEtudiant():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashbordEtudiant'))
    return render_template('loginEtudiant.html', form=form)



@app.route('/ChangePassword', methods=["GET", "POST"])
def ChangePassword():
    if request.method == "POST":
        username = request.form['username']
        changementMotDePasse
        old_password = request.form.get('old_password',False)
        new_password = request.form.get('new_password',False)
        user = User.query.filter_by(username=username).first()
        passwo = User.query.filter_by(password=old_password).first()
        if user:
            if passwo:
                user.password = new_password
                db.session.commit()
                msg = "Changed successfully"
                flash('Changed successfully.', 'success')
                return render_template("ChangePassword.html", success=msg)
            else:
                error = "Wrong password"
                return render_template("ChangePassword.html", error=error)
        else:
            return render_template("ChangePassword.html")
    return render_template("ChangePassword.html")


@app.route('/examCode', methods=['POST'])
def examCode():
    exam_code = request.form['exam_code']
    #exam = Exam.query.filter_by(exam_code=exam_code).first()
    if exam_code in Exam.identifier:
        questions = Exam.identifier[exam_code]
        qanda = [] #qanda = question and answers
        for question in questions:
            answers = json.loads(question.answers.replace("'", '"'))
            qanda.append(
                {'id': question.id, 'question': question.question, 'answers': [item["reponse"] for item in answers],
                 'correct_answers': [item["reponse"] for item in answers if item["correcte"] == "true"]})

        return redirect(url_for('my-questionsEtudiant', questions=qanda))
    else:
        return render_template('examCode.html', error="Code d'examen incorrect")

@app.route("/my_questionsEtudiant", methods=["GET", "POST"])  # Chemin de la page de création de question
@login_required
def personal_questions_Etudiant():  # Page d'affichage des questions
    questions = Question.query.filter_by(id_user=current_user.id).all()
    qanda = [] #qanda = question and answers
    for question in questions:
        answers = json.loads(question.answers.replace("'", '"'))
        qanda.append(
            {'id': question.id, 'question': question.question, 'answers': [item["reponse"] for item in answers],
             'correct_answers': [item["reponse"] for item in answers if item["correcte"] == "true"]})

    return render_template("my_questionsEtudiant.html", questions=qanda, user=current_user)

# CREATION EXAMEN
class ExamCreationForm(FlaskForm):
    questions = SelectMultipleField('Select Questions', coerce=int, validators=[DataRequired()], choices=[])
    num_questions = SelectField('Number of Questions', choices=[(str(i), str(i)) for i in range(1, 11)],
                                validators=[DataRequired()])
    submit = SubmitField('Create Quiz')


@app.route('/create_exam', methods=['GET', 'POST'])
@login_required
def create_exam():
    form = ExamCreationForm()
    questions = Question.query.filter_by(id_user=current_user.id).all()
    form.questions.choices = [(question.id, question.question) for question in questions]
    if form.validate_on_submit():
        questions = Question.query.filter_by(id_user=current_user.id).all()
        selected_questions = [question for question in questions if question.id in form.questions.data]
        identifier = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(6))
        exam = Exam(id_user=current_user.id, questions=json.dumps([question.to_json() for question in selected_questions]),
                    num_questions=form.num_questions.data, identifier=identifier)
        db.session.add(exam)
        db.session.commit()
        flash('Exam created successfully', 'success')
        return redirect(url_for('my_exams'))
    return render_template('create_exam.html', form=form)


if __name__ == "__main__":
    # ''.join(random.choices(string.ascii_letters + string.digits, k=16))

    with app.app_context():
        db.create_all()
    socketio.run(app,debug = True)

