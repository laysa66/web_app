import json
from flask import Flask, render_template, url_for, redirect, jsonify, request, flash ,session
from flask_bcrypt import Bcrypt
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm, Form
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, BooleanField, SelectField
from werkzeug.utils import secure_filename
from wtforms.validators import InputRequired, Length, ValidationError
from flask_change_password import ChangePassword, ChangePasswordForm, SetPasswordForm
from datetime import datetime
import os
import pandas as pd
# utilisation du FLASK_LOGIN: https://flask-login.readthedocs.io/en/latest/
# creation de la base de donnees LOCALE avec SQLALCHEMY: https://flask-sqlalchemy.palletsprojects.com/en/2.x/quickstart/
#la difference entre SQLALCHEMY et SQLITE3: SQLAlchemy est une bibliothèque de mappage objet-relationnel pour Python qui
# permet de travailler avec des bases de données en utilisant des classes Python plutôt que des requêtes SQL brutes. SQL,
# ou Structured Query Language, est un langage de programmation utilisé pour communiquer avec des bases de données relationnelles,
# comme MySQL, PostgreSQL et SQLite. SQLAlchemy permet de générer automatiquement des requêtes SQL à partir de code Python,
# tandis que SQL est utilisé pour écrire manuellement des requêtes pour interagir avec des bases de données.


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///passeword.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'thisisasecretkey'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.secret_key = os.urandom(20)
flask_change_password = ChangePassword(min_password_length=10, rules=dict(long_password_override=2))
flask_change_password.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


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
    submit = SubmitField('Créer la question', render_kw={"class": "btn btn-success"})

# fonction pour verifier si la question est dans la base de donnees ou non (pour la creation d'une question)
    def validate_question(self, question):
        existing_question = Question.query.filter_by(
            question=question.data).first()
        if existing_question:
            return True
        return False
# fonction pour les reponses des questions
    def validate_question_answers(self, i, q):
        existing = Question.query.filter(Question.question == q.data, Question.id != i).first()
        if existing:
            return True
        return False

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
    #if current_user.type_user != 'teacher':
        #return render_template('etudiant.html', user=current_user)
    return render_template('accueil.html', user=current_user)

# route pour aller a la page de connexion (login) et  verifier si le nom d'utilisateur
# et le mot de passe sont corrects,  si oui, on va a la page d'accueil
@app.route('/accueil2', methods=['GET', 'POST'])
def accueil2():
    return render_template('accueil2.html', user=current_user)
app.route('/next', methods=['GET', 'POST'])
def next():
    return render_template('accueil2.html'
                           )
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
#----------------------------------------------------------------------------------------------------------------------------#

# partie creation de question

@app.route("/create_question", methods=["GET", "POST"])  # Chemin de la page de création de question
@login_required
def create_question():  # Page de création de question
    form = QuestionForm()
    if form.validate_on_submit():
        answers = []
        for i in range(1, 5):
            answers.append({"reponse": form[f"answer{i}"].data, "correcte": str(form[f"correct{i}"].data).lower()})
        new_question = Question(question=form.question.data, id_user=current_user.id, answers=str(answers))
        try:
            if form.validate_question(form.question):
                return render_template('create_question.html', form=form,
                                       error="Question déjà créee ! il faut la modifier "
                                             "dans la section 'Modifier une question'")
            db.session.add(new_question)
            db.session.commit()
            return redirect(url_for('personal_questions'))
        except Exception as e:
            print(e)
            return "Il y a eu un problème lors de l'ajout de la question"
    return render_template("create_question.html", form=form, error="")

# route pour aller a la page de modification de question
@app.route("/modify_question/<int:question_id>", methods=["GET", "POST"])
@login_required
def modify_question(question_id):
    form = QuestionForm()
    form.submit.label.text = "Modifier la question"
    question = Question.query.get(question_id)
    if question is None:
        return f"La question dont l'id {question_id} n'existe pas", 404
    else:
        if question.id_user != current_user.id: # Si l'utilisateur n'est pas le propriétaire de la question, il ne pourra pas la modifier
            return f"Vous n'avez pas les droits pour modifier cette question", 403
    if form.validate_on_submit():
        if form.validate_question_answers(question_id, form.question):
            return render_template('create_question.html', form=form, error="Question déjà crée !")
        answers = []
        for i in range(1, 5):
            answers.append({"reponse": form[f"answer{i}"].data, "correcte": str(form[f"correct{i}"].data).lower()})
        question.question = form.question.data
        question.answers = str(answers)
        try:
            db.session.commit()
            return redirect(url_for('personal_questions') + f"#preview-{question_id}")
        except Exception as e:  # Si il y a une erreur lors de la modification de la question
            print(e)
            return "Il y a eu un problème lors de la modification de la question"
    else:
        form.question.data = question.question
        answers = json.loads(question.answers.replace("'", '"'))
        for i, answer in enumerate(answers):
            form[f"answer{i + 1}"].data = answer["reponse"]
            form[f"correct{i + 1}"].data = True if answer["correcte"] == "true" else False

    return render_template("update_question.html", form=form, question_id=question_id)

@app.route("/my_questions", methods=["GET", "POST"])  # Chemin de la page de création de question
@login_required
def personal_questions():  # Page d'affichage des questions
    questions = Question.query.filter_by(id_user=current_user.id).all()
    qanda = [] #qanda = question and answers
    for question in questions:
        answers = json.loads(question.answers.replace("'", '"'))
        qanda.append(
            {'id': question.id, 'question': question.question, 'answers': [item["reponse"] for item in answers],
             'correct_answers': [item["reponse"] for item in answers if item["correcte"] == "true"]})

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


@app.route('/delete/<int:question_id>', methods=['DELETE']) # Chemin de la page de supression de question
@login_required
def delete_question(question_id): # Fonction de suppression de question
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
#elle affiche que celles avec true
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
@app.route('/accueilEtudiant')
def accueilEtudiant():
    return render_template('accueilEtudiant.html')

@app.route('/dashbordEtudiant',methods=['GET', 'POST'])
@login_required
def dashbordEtudiant():
    return render_template('dashbordEtudiant.html')

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
            flash('Changed successfully.', 'success')
            return render_template("ChangePassword.html", success=msg)
        else:
            error = "Username not found"
            return render_template("ChangePassword.html", error=error)
    return render_template("ChangePassword.html")


@app.route('/examCode', methods=['POST'])
def examCode():
    exam_code = request.form['exam_code']
    return render_template('examCode.html', exam_code=exam_code)

#df = pd.read_csv('input/ ')
#df.to_sql('users',con=db.engine, if_exists='append', index=False)

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5005)
