import csv
import json
import os
import secrets
import string
from datetime import datetime

import pandas as pd
from flask import (Flask, flash, jsonify, redirect, render_template, request,
                   session, url_for, send_file)
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
                     TextAreaField, IntegerField)
from wtforms.validators import (DataRequired, InputRequired, Length,
                                ValidationError)
from fpdf import FPDF
import random


# utilisation du FLASK_LOGIN: https://flask-login.readthedocs.io/en/latest/
# creation de la base de donnees LOCALE avec SQLALCHEMY: https://flask-sqlalchemy.palletsprojects.com/en/2.x/quickstart/
# la difference entre SQLALCHEMY et SQLITE3: SQLAlchemy est une bibliothèque de mappage objet-relationnel pour Python qui
# permet de travailler avec des bases de données en utilisant des classes Python plutôt que des requêtes SQL brutes. SQL,
# ou Structured Query Language, est un langage de programmation utilisé pour communiquer avec des bases de données relationnelles,
# comme MySQL, PostgreSQL et SQLite. SQLAlchemy permet de générer automatiquement des requêtes SQL à partir de code Python,
# tandis que SQL est utilisé pour écrire manuellement des requêtes pour interagir avec des bases de données.


app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "thisisasecretkey"
socketio = SocketIO(app, cors_allowed_origins="*")
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.secret_key = os.urandom(20)
flask_change_password = ChangePassword(
    min_password_length=10, rules=dict(long_password_override=2)
)
flask_change_password.init_app(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

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
    questions = db.Column(db.String(255), nullable=False)
    identifier = db.Column(db.String(255), nullable=False)
    ended = db.Column(db.Boolean, nullable=False, default=False)


class Answer(db.Model, UserMixin):  # table base de données
    id = db.Column(db.Integer, primary_key=True)
    id_user = db.Column(db.Integer, db.ForeignKey(User.id), nullable=False)
    id_question = db.Column(db.Integer, db.ForeignKey(Question.id), nullable=False)
    answers = db.Column(db.String(255), nullable=False)
    identifier = db.Column(db.Integer, db.ForeignKey(Exam.id), nullable=False)


# utilisation de flask login pour la connexion et la déconnexion d'un utilisateur
# ICI pour plus d'informations : https://youtu.be/71EU8gnZqZQ


class RegisterForm(FlaskForm):
    username = StringField(
        validators=[InputRequired(), Length(min=4, max=20)],
        render_kw={"placeholder": "Pseudonyme", "id": "username"},
    )
    firstname = StringField(
        validators=[InputRequired(), Length(min=4, max=150)],
        render_kw={"placeholder": "Nom", "id": "firstname"},
    )
    lastname = StringField(
        validators=[InputRequired(), Length(min=4, max=150)],
        render_kw={"placeholder": "Prénom", "id": "lastname"},
    )
    password = PasswordField(
        validators=[InputRequired(), Length(min=8, max=20)],
        render_kw={"placeholder": "Mot de passe", "id": "password"},
    )
    select_type_user = SelectField(
        "Type d'utilisateur",
        choices=[("teacher", "Professeur"), ("student", "Etudiant")],
        validators=[InputRequired()],
        render_kw={"id": "usertype"},
    )
    submit = SubmitField("Register")

    # fonction pour verifier si le nom d'utilisateur existe deja dans la base de donnees ou non (pour l'inscription)

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            return True
        return False


# classe pour le formulaire de creation de question
class QuestionForm(FlaskForm):
    question = TextAreaField(
        "Question",
        validators=[InputRequired()],
        render_kw={"rows": "4", "id": "question", "class": "form-control"},
    )
    answer1 = StringField(
        "Réponse 1",
        validators=[InputRequired()],
        render_kw={"id": "answer1", "class": "form-control"},
    )
    answer2 = StringField(
        "Réponse 2",
        validators=[InputRequired()],
        render_kw={"id": "answer2", "class": "form-control"},
    )
    answer3 = StringField(
        "Réponse 3",
        validators=[InputRequired()],
        render_kw={"id": "answer3", "class": "form-control"},
    )
    answer4 = StringField(
        "Réponse 4",
        validators=[InputRequired()],
        render_kw={"id": "answer4", "class": "form-control"},
    )
    correct1 = BooleanField(
        "Réponse correcte", default=False, render_kw={"class": "form-check-input"}
    )
    correct2 = BooleanField(
        "Réponse correcte", default=False, render_kw={"class": "form-check-input"}
    )
    correct3 = BooleanField(
        "Réponse correcte", default=False, render_kw={"class": "form-check-input"}
    )
    correct4 = BooleanField(
        "Réponse correcte", default=False, render_kw={"class": "form-check-input"}
    )

    tags = SelectMultipleField(
        "Tags",
        choices=[],
        validators=[InputRequired()],
        render_kw={"id": "tags", "class": "form-control"},
    )

    submit = SubmitField("Créer la question", render_kw={"class": "btn btn-success"})


# class login pour la connexion
class LoginForm(FlaskForm):
    username = StringField(
        validators=[InputRequired(), Length(min=4, max=20)],
        render_kw={"placeholder": "Nom d'utilisateur", "id": "username"},
    )

    password = PasswordField(
        validators=[InputRequired(), Length(min=8, max=20)],
        render_kw={"placeholder": "Mot de passe", "id": "password"},
    )

    submit = SubmitField("LOGIN", render_kw={"id": "submit"})


class ExamCreationForm(FlaskForm):
    questions = SelectMultipleField(
        "Choisissez les questions que vous souhaitez inclure dans votre examen",
        choices=[],
        validators=[DataRequired()],
    )
    submit = SubmitField(
        "Create Quiz", render_kw={"class": "btn btn-success", "id": "submit"}
    )

class PdfCreationForm(FlaskForm):
    tags=SelectMultipleField(
        "Choisissez les tags que vous souhaitez inclure dans votre pdf",
        choices=[],
        validators=[DataRequired()],
        render_kw={"id": "tags", "class": "form-control"},
    )
    nb_questions=IntegerField(
        "Choisissez le nombre de questions que vous souhaitez inclure dans votre pdf",
        validators=[DataRequired()],
        render_kw={"id": "nb_questions", "class": "form-control"},
    )
    nb_copies=IntegerField(
        "Choisissez le nombre de copies que vous souhaitez inclure dans votre pdf",
        validators=[DataRequired()],
        render_kw={"id": "nb_copies", "class": "form-control"},
    )
    submit = SubmitField(
        "Create PDF", render_kw={"class": "btn btn-success", "id": "submit"}
    )


@app.route("/")
@login_required
# route pour aller a la page d'accueil
def accueil():
    # if current_user.type_user != 'teacher':
    # return render_template('etudiant.html', user=current_user)
    return render_template("accueil.html", user=current_user)


# route pour aller a la page de connexion (login) et  verifier si le nom d'utilisateur
# et le mot de passe sont corrects,  si oui, on va a la page d'accueil
@app.route("/accueil2", methods=["GET", "POST"])
def accueil2():
    return render_template("accueil2.html", user=current_user)


@app.route("/next", methods=["GET"])
def nextPage():
    return redirect(url_for("accueil2"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("accueil"))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                if current_user.type_user == "teacher":
                    return redirect(url_for("accueil"))
                else:
                    return redirect(url_for("etudiant"))
    return render_template("login.html", form=form)


@app.route("/etudiant ", methods=["GET", "POST"])
def etudiant():
    return render_template("etudiant.html", user=current_user)


# route pour aller a la page de deconnexion (logout) et  deconnecter l'utilisateur
@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/next", methods=["GET", "POST"])
def next():
    return redirect(url_for("accueil2"))


@app.route("/back", methods=["GET", "POST"])
def back():
    return redirect(url_for("accueil"))


# route pour aller a la page d'inscription (register)
@app.route("/register", methods=["GET", "POST"])
def register():
    # si l'utilisateur est connecté on le redirige vers la page dashboard
    if current_user.is_authenticated:
        return redirect(url_for("accueil"))
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(
            username=form.username.data,
            password=hashed_password,
            first_name=form.firstname.data,
            last_name=form.lastname.data,
            type_user=form.select_type_user.data,
        )
        try:
            if form.validate_username(form.username):
                return render_template(
                    "register.html", form=form, error="Pseudunyme déjà utilisé"
                )
            db.session.add(new_user)
            db.session.commit()
        except Exception as e:
            print(e)
            return "Il y a eu un problème lors de l'inscription"
        return redirect(url_for("login"))

    return render_template("register.html", form=form, error="")


# ----------------------------------------------------------------------------------------------------------------------------#

# partie creation de question
def validate_question(question):
    existing_question = Question.query.filter_by(question=question).first()
    if existing_question:
        return True
    return False


# fonction pour les reponses des questions
def validate_question_answers(i, q, answers, tags):
    existing = Question.query.filter(
        Question.question == q,
        Question.id == i,
        Question.answers == answers,
        Question.tags == tags,
    ).first()
    if existing:
        return True
    return False


@app.route(
    "/create_question", methods=["GET", "POST"]
)  # Chemin de la page de création de question
@login_required
def create_question():  # Page de création de question
    if request.method == "POST":
        form = json.loads(request.data)
        answers = []
        for i in range(1, 5):
            answers.append(
                {
                    "reponse": form["answers"][f"answer{i}"].replace("'", "''"),
                    "correcte": str(form["correct"][f"correct{i}"]).lower(),
                }
            )
        new_question = Question(
            question=form["question"].replace("'", "''"),
            id_user=current_user.id,
            answers=str(answers),
            tags=str(form["tags"]),
        )
        try:
            if validate_question(form["question"]):
                return jsonify({"success": False, "error": "Question déjà existante !"})
            db.session.add(new_question)
            db.session.commit()
            # return redirect(url_for('personal_questions'))
            # send json return data to client
            return jsonify({"success": True, "message": "Question créee avec succès !"})
        except Exception as e:
            print(e, "error")
            return "Il y a eu un problème lors de l'ajout de la question"
    return render_template("create_question.html", error="")


# route pour aller a la page de modification de question
@app.route("/modify_question/<int:question_id>", methods=["GET", "POST"])
@login_required
def modify_question(question_id):
    question = Question.query.filter_by(id=question_id).first()
    if question is None:
        return f"La question dont l'id {question_id} n'existe pas", 404
    elif (
        question.id_user != current_user.id
    ):  # Si l'utilisateur n'est pas le propriétaire de la question, il ne pourra pas la modifier
        return f"Vous n'avez pas les droits pour modifier cette question", 403
    if request.method == "POST":
        form = json.loads(request.data)

        answers = []
        for i in range(1, 5):
            answers.append(
                {
                    "reponse": form["answers"][f"answer{i}"],
                    "correcte": str(form["correct"][f"correct{i}"]).lower(),
                }
            )

        if validate_question_answers(
            question_id, form["question"], str(answers), str(form["tags"])
        ):
            return jsonify({"success": False, "error": "Question déjà existante !"})

        question.question = form["question"]
        question.answers = str(answers)
        question.tags = str(form["tags"])

        try:
            db.session.commit()
            return jsonify(
                {"success": True, "message": "Question modifiée avec succès !"}
            )
        except Exception as e:  # Si il y a une erreur lors de la modification de la question
            print(e)
            return "Il y a eu un problème lors de la modification de la question"
    else:
        data = {
            "question": question.question,
            "answers": json.loads(question.answers.replace("'", '"')),
            "tags": json.loads(question.tags.replace("'", '"')),
        }
        return render_template(
            "update_question.html", form=data, question_id=question_id
        )


@app.route(
    "/my_questions", methods=["GET", "POST"]
)  # Chemin de la page de création de question
@login_required
def personal_questions():  # Page d'affichage des questions
    questions = Question.query.filter_by(id_user=current_user.id).all()
    qanda = []  # qanda = question and answers
    for question in questions:
        tags = json.loads(question.tags.replace("'", '"'))
        print(question.answers)
        # on échappe les apostrophes pour que json.loads fonctionne
        question.answers = question.answers.replace("'", '"')
        
        answers = json.loads(question.answers.replace('""', "'"))
        qanda.append(
            {
                "id": question.id,
                "question": question.question,
                "answers": [item["reponse"] for item in answers],
                "correct_answers": [
                    item["reponse"] for item in answers if item["correcte"] == "true"
                ],
                "tags": tags,
            }
        )

    return render_template("my_questions.html", questions=qanda, user=current_user)


@app.route("/questions", methods=["GET"])  # Chemin de la page de création de question
@login_required
def all_questions():  # Page d'affichage des questions
    questions = Question.query.all()
    qanda = []
    for question in questions:
        tags = json.loads(question.tags.replace("'", '"'))
        question.answers = question.answers.replace("'", '"')
        
        answers = json.loads(question.answers.replace('""', "'"))
        qanda.append(
            {
                "id": question.id,
                "question": question.question,
                "answers": [item["reponse"] for item in answers],
                "correct_answers": [
                    item["reponse"] for item in answers if item["correcte"] == "true"
                ],
                "tags": tags,
            }
        )

    return render_template("all_questions.html", questions=qanda)


@app.route(
    "/delete/<int:question_id>", methods=["DELETE"]
)  # Chemin de la page de supression de question
@login_required
def delete_question(question_id):  # Fonction de suppression de question
    question = Question.query.get(question_id)
    if question:
        if question.id_user != current_user.id:
            return (
                jsonify(
                    {
                        "message": "Vous n'avez pas les droits pour supprimer cette question"
                    }
                ),
                403,
            )
        db.session.delete(question)
        db.session.commit()
        return jsonify({"message": "La question a été supprimé", "status": 200}), 200
    else:
        return (
            jsonify(
                {
                    "message": f"La question dont l'id {question_id} n'existe pas dans la base de données",
                    "status": 404,
                }
            ),
            404,
        )


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


@app.route("/accueilEtudiant")
def accueilEtudiant():
    return render_template("accueilEtudiant.html")


@app.route("/dashbordEtudiant", methods=["GET", "POST"])
@login_required
def dashbordEtudiant():
    return render_template("dashbordEtudiant.html")


# csv part
ALLOWED_EXTENSIONS = set(["csv"])


def allowed_file(filename):  # the filename contains the csv extension
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def logoutEtudiant_user():
    pass


@app.route("/logoutEtudiant", methods=["GET", "POST"])
@login_required
def logoutEtudiant():
    logout_user()
    return redirect(url_for("login"))


@app.route("/registerEtudiant", methods=["GET", "POST"])
def registerEtudiant():
    # si l'utilisateur est connecté on le redirige vers la page dashboard
    if current_user.is_authenticated:
        return redirect(url_for("accueilEtudiant"))
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(
            username=form.username.data,
            password=hashed_password,
            first_name=form.firstname.data,
            last_name=form.lastname.data,
        )
        try:
            if form.validate_username(form.username):
                return render_template(
                    "registerEtudiant.html", form=form, error="Pseudunyme déjà utilisé"
                )
            db.session.add(new_user)
            db.session.commit()
        except Exception as e:
            print(e)
            return "Il y a eu un problème lors de l'inscription"
        return redirect(url_for("login"))

    return render_template("registerEtudiant.html", form=form, error="")


"""@app.route('/ChangePassword', methods=["GET", "POST"])
def ChangePassword():
    if request.method == "POST":
        username = request.form['username']
        newPassword = request.form['newpassword']
        user = User.query.filter_by(username=username).first()
        if user:
            user.password = newPassword
            db.session.commit()
            msg = "Changed successfully"
            return render_template("ChangePassword.html", success=msg)
        else:
            error = "Username not found"
            return render_template("ChangePassword.html", error=error)
    return render_template("ChangePassword.html")"""


@login_required
@app.route("/upload_users", methods=["GET", "POST"])
def upload_file():
    if request.method == "POST":
        file = request.files["file"]
        if file:
            # Read the CSV file
            reader = csv.DictReader(
                file.stream.read().decode("utf-8").splitlines(), delimiter=";"
            )
            errors = []
            for row in reader:
                # Add the user to the database
                new_user = User(
                    username=row["username"],
                    password=bcrypt.generate_password_hash(row["password"]),
                    first_name=row["firstname"],
                    last_name=row["lastname"],
                    type_user=row["type_user"],
                )
                try:
                    db.session.add(new_user)
                    db.session.commit()
                except Exception as e:
                    print(e)
                    errors.append(row)
            errtext = (
                f"Il y a eu des erreurs lors du chargement des utilisateurs suivants\n {errors}"
                if len(errors) > 0
                else ""
            )
            return jsonify(
                {
                    "success": True,
                    "message": f"Fichier importé avec succès !\n{errtext}",
                }
            )
    # Render an HTML form that allows the user to select a CSV file
    return render_template("upload.html")


# partie de mahmoud
@app.route("/loginEtudiant", methods=["GET", "POST"])
def loginEtudiant():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for("dashbordEtudiant"))
    return redirect(url_for("login"))


@app.route("/ChangePassword", methods=["GET", "POST"])
def ChangePassword():
    if request.method == "POST":
        username = request.form["username"]
        # changementMotDePasse
        old_password = request.form.get("old_password", False)
        new_password = request.form.get("new_password", False)
        user = User.query.filter_by(username=username).first()
        passwo = bcrypt.check_password_hash(user.password, old_password)
        if user:
            if passwo:
                user.password = bcrypt.generate_password_hash(new_password)
                db.session.commit()
                msg = "Changed successfully"
                flash("Changed successfully.", "success")
                return render_template("ChangePassword.html", success=msg)
            else:
                error = "Wrong password"
                return render_template("ChangePassword.html", error=error)
        else:
            return render_template("ChangePassword.html")
    return render_template("ChangePassword.html")


@app.route("/examCode", methods=["GET"])
def examCode():
    exam_code = request.form["exam_code"]
    # exam = Exam.query.filter_by(exam_code=exam_code).first()
    if exam_code in Exam.identifier:
        questions = Exam.identifier[exam_code]
        qanda = []  # qanda = question and answers
        for question in questions:
            answers = json.loads(question.answers.replace("'", '"'))
            qanda.append(
                {
                    "id": question.id,
                    "question": question.question,
                    "answers": [item["reponse"] for item in answers],
                    "correct_answers": [
                        item["reponse"]
                        for item in answers
                        if item["correcte"] == "true"
                    ],
                }
            )

        return redirect(url_for("my-questionsEtudiant", questions=qanda))
    else:
        return render_template("examCode.html", error="Code d'examen incorrect")


@app.route(
    "/my_questionsEtudiant", methods=["GET", "POST"]
)  # Chemin de la page de création de question
@login_required
def personal_questions_Etudiant():  # Page d'affichage des questions
    questions = Question.query.filter_by(id_user=current_user.id).all()
    qanda = []  # qanda = question and answers
    for question in questions:
        answers = json.loads(question.answers.replace("'", '"'))
        qanda.append(
            {
                "id": question.id,
                "question": question.question,
                "answers": [item["reponse"] for item in answers],
                "correct_answers": [
                    item["reponse"] for item in answers if item["correcte"] == "true"
                ],
            }
        )

    return render_template(
        "my_questionsEtudiant.html", questions=qanda, user=current_user
    )


# CREATION EXAMEN
@app.route("/create_exam", methods=["GET", "POST"])
@login_required
def create_exam():
    form = ExamCreationForm()
    questions = Question.query.filter_by(id_user=current_user.id).all()
    form.questions.choices = [
        (question.id, question.question, question.tags) for question in questions
    ]
    if request.method == "POST":
        print(request.form)
        # Récupération des id questions sélectionnées avec request.form
        selected_questions = request.form.getlist("questions")
        identifier = "".join(
            secrets.choice(string.ascii_uppercase + string.digits) for _ in range(6)
        )
        print(selected_questions)
        exam = Exam(
            identifier=identifier,
            questions=json.dumps(selected_questions),
            id_user=current_user.id,
            ended=False,
        )
        db.session.add(exam)
        db.session.commit()
        print("Exam created successfully")
        # Si pas d'erreur, on emet un signal pour lancer l'examen
        if exam:
            emit("start_exam", identifier, broadcast=True, namespace="/")
            print("Exam started")
        return redirect(url_for("created_exam", identifier=identifier))
    else:
        print("Error while creating exam")

    return render_template("create_exam.html", form=form)


@app.route("/created_exam/<identifier>", methods=["GET"])
@login_required
def created_exam(identifier):
    return render_template("created_exam.html", identifier=identifier)


# SocketIO pour l'examen
@socketio.on("connect")
def connect():
    print("Client connected")


@socketio.on("stop_exam")
def stop_exam(data):
    print("Exam stopped")
    print(data)
    print(type(data))
    # On met à jour l'examen en base de données
    exam = Exam.query.filter_by(identifier=data["identifier"]).first()
    print(exam)
    print(type(exam))
    exam.ended = True
    db.session.commit()
    emit("exam_stopped", data['identifier'], broadcast=True, namespace="/")


@socketio.on("disconnect")
def disconnect():
    print("Client disconnected")


@socketio.on("join_exam")
def join_exam(identifier):
    # On vérifie si l'identifiant de l'examen est correct
    if identifier in Exam.identifier and not Exam.identifier[identifier].ended:
        # On récupère les questions de l'examen
        questions = Question.query.filter(
            Question.id.in_(Exam.identifier[identifier])
        ).all()
        qanda = []  # qanda = question and answers
        for question in questions:
            ans = question.answers.replace("'", '"')
            answers = json.loads(ans.replace('""', "'"))
            
            qanda.append(
                {
                    "id": question.id,
                    "question": question.question,
                    "answers": [item["reponse"] for item in answers],
                    "correct_answers": [
                        item["reponse"]
                        for item in answers
                        if item["correcte"] == "true"
                    ],
                }
            )
        # On envoie les questions à l'étudiant
        emit("questions", qanda)
    else:
        emit("exam_not_found")


@socketio.on("answer")
def answer(data):
    # Ajouter la réponse à la base de données
    print(data)
    answer = Answer(
        id_user=data["id_user"],
        id_question=data["id_question"],
        answers=json.dumps(data["answer"]),
        identifier=data["identifier"],
    )
    db.session.add(answer)
    db.session.commit()
    print(
        "Réponse ajoutée de l'étudiant"
        + str(data["id_user"])
        + " à la question "
        + str(data["id_question"])
    )


@app.route("/join_exam", methods=["GET", "POST"])
@login_required
def join_exam():
    if request.method == "POST":
        # Cas ou vide
        if not request.form["identifier"]:
            return render_template("join_exam.html")
        identifier = request.form["identifier"]
        exam = Exam.query.filter_by(identifier=identifier).first()
        questions_ids = json.loads(exam.questions)
        print(questions_ids)
        # Récupérer les question par leur id dans la table exam
        questions = Question.query.filter(Question.id.in_(questions_ids)).all()
        qanda = []  # qanda = question and answers
        for question in questions:
            ans = question.answers.replace("'", '"')
            answers = json.loads(ans.replace('""', "'"))
            qanda.append(
                {
                    "id": question.id,
                    "question": question.question,
                    "answers": [item["reponse"] for item in answers],
                    "correct_answers": [
                        item["reponse"]
                        for item in answers
                        if item["correcte"] == "true"
                    ],
                }
            )
        print(qanda)
        if exam:
            if exam.ended:
                return redirect(url_for("exam_ended"))
            # si tout est ok, on envoie l'étudiant sur la page de l'examen
            return redirect(
                url_for("exam", identifier=identifier, questions=json.dumps(qanda))
            )
        else:
            flash("Cet examen n'existe pas")
            return redirect(url_for("etudiant"))
    return render_template("join_exam.html")


@app.route("/exam", methods=["GET"])
@login_required
def exam():
    identifier = request.args.get("identifier")
    questions = request.args.get("questions")
    questions_json = json.loads(questions)
    questions_len = len(questions_json)
    id_user = current_user.id
    return render_template(
        "exam.html",
        identifier=identifier,
        questions=questions_json,
        questions_len=questions_len,
        id_user=id_user,
    )


@app.route("/exam_ended", methods=["GET", "POST"])
@login_required
def exam_ended():
    return render_template("exam_ended.html")


@app.route("/generate_pdf", methods=["GET", "POST"])
@login_required
def generate_pdf():
    #On récupère les tags de toutes les questions de l'utilisateur
    tags = Question.query.with_entities(Question.tags).filter_by(id_user=current_user.id).all()
    form = PdfCreationForm()
    form.tags.choices = list(set([(tag[0], tag[0]) for tag in tags]))
    if form.validate_on_submit():
        tags = form.tags.data
        print(tags)
        nb_questions = form.nb_questions.data
        print(nb_questions)
        nb_copies = form.nb_copies.data
        print(nb_copies)
        # On récupère les questions
        questions = Question.query.filter(Question.tags.in_(tags)).all()
        qanda = []  # qanda = question and answers
        for question in questions:
            ans = question.answers.replace("'", '"')
            answers = json.loads(ans.replace('""', "'"))
            qanda.append(
                {
                    "id": question.id,
                    "question": question.question,
                    "answers": [item["reponse"] for item in answers],
                    "correct_answers": [
                        item["reponse"]
                        for item in answers
                        if item["correcte"] == "true"
                    ],
                }
            )
        # On génère le pdf
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        for i in range(nb_copies):
            pdf.cell(200, 10, txt="Copie n°" + str(i + 1), ln=1, align="C")
            for j in range(nb_questions):
                question = random.choice(qanda)
                pdf.cell(200, 10, txt=question["question"], ln=1, align="L")
                for answer in question["answers"]:
                    pdf.cell(200, 10, txt=answer, ln=1, align="L")
                pdf.cell(200, 10, txt="", ln=1, align="L")
            pdf.cell(200, 10, txt="", ln=1, align="L")
        
            pdf.add_page()
        pdf.output("test.pdf")
        return send_file("test.pdf", as_attachment=True)

    return render_template("generate_pdf.html", form=form)


if __name__ == "__main__":
    # ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    with app.app_context():
        db.create_all()
    socketio.run(app, debug=True)
