import os.path
from flask import Flask, render_template, request, redirect, url_for
from flask_login import login_user, LoginManager, \
    login_required, logout_user, current_user
from flask_restful import Api
from sqlalchemy.orm import sessionmaker
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from database_setup import *

app = Flask(__name__)
app.config['SECRET_KEY'] = '123'
app.config['UPLOAD_FOLDER'] = 'static/images/'

# Подключаемся и создаем сессию базы данных
engine = create_engine('sqlite:///messenger.db?check_same_thread=False', echo=True)
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return session.query(User).filter_by(Id=user_id).first()


@app.route('/', methods=['POST', 'GET'])
@login_required
def index():
    user_id = current_user.Id

    # Вывод переписок
    user_chats = session.query(ChatParticipant).filter(ChatParticipant.UserId == str(user_id)).all()
    chats = []
    for user_chat in user_chats:
        personal_chat = session.query(ChatParticipant, Chat, User). \
            filter(and_(ChatParticipant.ChatId == user_chat.ChatId, ChatParticipant.UserId != user_id)). \
            join(Chat, and_(Chat.Id == ChatParticipant.ChatId, Chat.Type == 0)). \
            join(User, User.Id == ChatParticipant.UserId).order_by(asc(Chat.Date)).first()

        group_chat = session.query(ChatParticipant, Chat). \
            filter(and_(ChatParticipant.ChatId == user_chat.ChatId, ChatParticipant.UserId == user_id)). \
            join(Chat, and_(Chat.Id == ChatParticipant.ChatId, Chat.Type == 1)).first()

        if personal_chat:
            personal_chat.Chat.Name = "@" + str(personal_chat.User.Login) + " : " + str(personal_chat.User.Name)
            chats.append(personal_chat)
        elif group_chat:
            chats.append(group_chat)

    # Создание новой переписки
    if request.args.get('new_contact_id'):
        new_contact_id = request.args.get('new_contact_id')

        if new_contact_id == str(user_id):
            return redirect('/')

        for chat in chats:
            if chat.Chat.Type == 0 and str(chat.ChatParticipant.UserId) == str(new_contact_id):
                return redirect(url_for('index', chat_id=chat.Chat.Id))

        new_chat = Chat(Type=0)
        session.add(new_chat)
        session.commit()
        new_chat_paticipant1 = ChatParticipant(Status=1, UserId=user_id, ChatId=new_chat.Id)
        session.add(new_chat_paticipant1)
        session.commit()
        new_chat_paticipant2 = ChatParticipant(Status=1, UserId=new_contact_id, ChatId=new_chat.Id)
        session.add(new_chat_paticipant2)
        session.commit()

        return redirect(url_for('index', chat_id=new_chat.Id))

    # получение сообщений и вывод
    if request.args.get('chat_id'):
        chat_id = request.args.get('chat_id')

        # Получение информации о чате
        chat = session.query(Chat).filter(Chat.Id == chat_id).first()
        access = session.query(ChatParticipant). \
            filter(and_(ChatParticipant.ChatId == chat_id, ChatParticipant.UserId == user_id)).first()
        if not access:
            return redirect('/')

        # Новое сообщение
        if request.method == 'POST':
            try:
                message_text = request.form['message_text']
                new_content = Content(Text=message_text)
                session.add(new_content)
                session.commit()
                new_message = Message(ChatId=chat_id, SenderId=user_id, ContentId=new_content.Id)
                session.add(new_message)
                session.commit()
                return redirect(url_for('index', chat_id=chat_id))
            except:
                pass

        # Получение сообщений
        messages = session.query(Message, Chat, Content, User). \
            filter(Chat.Id == chat_id). \
            join(Chat, Message.ChatId == Chat.Id). \
            join(Content, Message.ContentId == Content.Id). \
            join(User, User.Id == Message.SenderId). \
            order_by(asc(Message.Date)).all()

        # Изменение статуса сообщения на прочитанно
        for message in messages:
            if message.Message.SenderId != user_id and message.Message.Status == 0:
                message.Message.Status = 1
            session.commit()

        # Результат поиска
        if request.method == 'POST':
            # поиск
            try:
                search = request.form['search']
                found_users = session.query(User).filter(or_(User.Name == search, User.Login == search)).all()
                return render_template('index.html', chats=chats, chat=chat, messages=messages, user_id=user_id,
                                       found_users=found_users)
            except:
                pass

        return render_template('index.html', chats=chats, chat=chat, messages=messages, user_id=user_id)

    # Результат поиска
    if request.method == 'POST':
        print("------------------------here---------------------------")
        # поиск
        try:
            search = request.form['search']
            found_users = session.query(User).filter(or_(User.Name == search, User.Login == search)).all()
            return render_template('index.html', chats=chats, found_users=found_users)
        except:
            pass

    if request.args.get('found_users'):
        found_users = request.args.get('found_users')
        return render_template('index.html', chats=chats, user_id=user_id)

    return render_template('index.html', chats=chats, user_id=user_id)


@app.route('/delete_message')
@login_required
def delete_message():
    user_id = current_user.Id

    if not request.args.get('chat_id') or not request.args.get('message_id'):
        return redirect('/')

    chat_id = request.args.get('chat_id')
    deleted_message_id = request.args.get('message_id')
    deleted_message = session.query(Message).filter(Message.Id == deleted_message_id).first()
    if deleted_message.SenderId != user_id:
        return redirect(url_for('index', chat_id=chat_id))

    deleted_message_content = session.query(Content).filter(Content.Id == deleted_message.ContentId).first()
    if deleted_message and deleted_message_content:
        session.delete(deleted_message_content)
        session.delete(deleted_message)
        session.commit()
    return redirect(url_for('index', chat_id=chat_id))


@app.route('/delete_chat')
@login_required
def delete_chat():
    user_id = current_user.Id

    if not request.args.get('chat_id'):
        return redirect('/')

    deleted_chat_id = request.args.get('chat_id')
    deleted_chat = session.query(Chat).filter(Chat.Id == deleted_chat_id).first()
    deleted_chat_participants = session.query(ChatParticipant).filter(ChatParticipant.ChatId == deleted_chat_id).all()

    for deleted_chat_participant in deleted_chat_participants:
        if deleted_chat_participant.UserId == user_id and deleted_chat_participant.Status == 0:
            return redirect('/')

    deleted_chat_messages = session.query(Message).filter(Message.ChatId == deleted_chat_id).all()
    if deleted_chat and deleted_chat_participants:
        for deleted_chat_participant in deleted_chat_participants:
            session.delete(deleted_chat_participant)
        for deleted_chat_message in deleted_chat_messages:
            session.delete(deleted_chat_message)
        session.delete(deleted_chat)
        session.commit()

    return redirect('/')


@app.route('/leave_chat')
@login_required
def leave_chat():
    user_id = current_user.Id

    if not (request.args.get('group_chat_id') or request.args.get('user_id')):
        return redirect('/')
    group_chat_id = request.args.get('group_chat_id')
    leaved_user_id = request.args.get('user_id')
    leaved_user = session.query(User).filter(User.Id == leaved_user_id).first()

    group_chat_participants = session.query(ChatParticipant, User).filter(ChatParticipant.ChatId == group_chat_id). \
        join(User, User.Id == ChatParticipant.UserId).all()

    admins_cnt = 0
    for group_chat_participant in group_chat_participants:
        if group_chat_participant.ChatParticipant.Status == 1:
            admins_cnt = admins_cnt + 1

    leaved_chat_participant = session.query(ChatParticipant). \
        filter(and_(ChatParticipant.ChatId == group_chat_id, ChatParticipant.UserId == leaved_user_id)).first()
    if leaved_chat_participant.Status == 1 and admins_cnt == 1:
        return redirect(url_for('edit_participants', group_chat_id=group_chat_id))

    # Сообщение о выходе из чата
    user_info = "@" + str(leaved_user.Login) + " : " + str(leaved_user.Name)
    message_text = user_info + " покинул нас"
    new_content = Content(Text=message_text)
    session.add(new_content)
    session.commit()
    new_message = Message(ChatId=group_chat_id, SenderId=user_id, ContentId=new_content.Id)
    session.add(new_message)
    session.commit()

    session.delete(leaved_chat_participant)
    session.commit()

    if not session.query(ChatParticipant).filter(ChatParticipant.ChatId == group_chat_id).all():
        return redirect(url_for('delete_chat', chat_id=group_chat_id))

    return redirect('/')


@app.route('/registration', methods=['POST', 'GET'])
def registration():
    data = ["", "", "", ""]

    if request.method == 'POST':
        name = request.form['name']
        login = request.form['login']
        password = request.form['password']
        password_hash = generate_password_hash(password)
        repeat_password = request.form['repeat_password']
        if data == [name, login, password, repeat_password]:
            return render_template('registration.html', data=data)

        data = [name, login, password, repeat_password]

        new_photo = request.files.get('photo_file')
        photo_name = '/static/images/icon.jpg'
        if new_photo:
            photo_name = secure_filename(new_photo.filename)
            new_photo.save(os.path.join(app.config['UPLOAD_FOLDER'], photo_name))
            photo_name = '/static/images/' + photo_name

        if session.query(User).filter(User.Login == login).first():
            error_message = "Такой логин уже существует"
            return render_template('registration.html', error_message=error_message, data=data)

        elif password != repeat_password:
            error_message = "Пароли не совпадают"
            return render_template('registration.html', error_message=error_message, data=data)

        new_user = User(Name=name, Photo=photo_name, Login=login, Password=password_hash)
        session.add(new_user)
        session.commit()

        login_user(new_user)
        return redirect('/')

    return render_template('registration.html', data=data)


@app.route('/login', methods=['POST', 'GET'])
def login():
    data = ["", ""]

    if request.method == 'POST':
        login = request.form['login']
        password = request.form['password']
        data = [login, password]
        user = session.query(User).filter(User.Login == login).first()

        # Проверка существования аккаунта с введеным логином
        if not user:
            error_message = "Аккаунта с таким логином не существует"
            return render_template('login.html', error_message=error_message, data=data)

        # Проверка правильности введеного пароля
        correct_password = check_password_hash(str(user.Password), password)
        if not correct_password:
            error_message = "Не верный пароль"
            return render_template('login.html', error_message=error_message, data=data)

        login_user(user)
        return redirect('/')

    return render_template('/login.html', data=data)


@app.route('/logout', methods=['POST', 'GET'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


def get_user_id(chat_name):
    all_users = session.query(User).all()
    for user in all_users:
        if chat_name == "@" + str(user.Login) + " : " + str(user.Name):
            user_id = user.Id
    return user_id


@app.route('/profile')
@login_required
def profile():
    current_user_id = current_user.Id
    user_id = current_user_id

    if request.args.get('user_info'):
        user_info = request.args.get('user_info')
        user_id = get_user_id(user_info)

    if request.args.get('user_id'):
        user_id = int(request.args.get('user_id'))

    user = session.query(User).filter(User.Id == user_id).first()
    return render_template('/profile.html', user=user, current_user_id=current_user_id)


@app.route('/edit_profile', methods=['POST', 'GET'])
@login_required
def edit_profile():
    user_id = current_user.Id
    user = session.query(User).filter(User.Id == user_id).first()

    if request.method == 'POST':
        new_name = request.form['name']
        new_photo = request.files.get('photo_file')
        photo_name = user.Photo
        if new_photo:
            photo_name = secure_filename(new_photo.filename)
            new_photo.save(os.path.join(app.config['UPLOAD_FOLDER'], photo_name))
            photo_name = '/static/images/' + photo_name
            user.Name = new_name
        user.Photo = photo_name
        session.commit()
        return redirect(url_for('profile', user_id=user_id))

    return render_template('/edit_profile.html', user=user)


@app.route('/create_group_chat', methods=['POST', 'GET'])
@login_required
def create_group_chat():
    user_id = current_user.Id

    new_group_chat = Chat(Type=1)
    session.add(new_group_chat)
    session.commit()
    new_group_chat_id = new_group_chat.Id
    new_group_chat_participant = ChatParticipant(ChatId=new_group_chat_id, UserId=user_id, Status=1)
    session.add(new_group_chat_participant)
    session.commit()

    return redirect(url_for('edit_group_chat', group_chat_id=new_group_chat_id))


@app.route('/edit_group_chat', methods=['POST', 'GET'])
@login_required
def edit_group_chat():
    user_id = current_user.Id
    if not request.args.get('group_chat_id'):
        return redirect('/')

    # получение данных о чате и о его участниках
    group_chat_id = request.args.get('group_chat_id')
    group_chat = session.query(Chat).filter(Chat.Id == group_chat_id).first()
    group_chat_participants = session.query(ChatParticipant, User).filter(ChatParticipant.ChatId == group_chat_id). \
        join(User, User.Id == ChatParticipant.UserId).order_by(desc(ChatParticipant.Status)).all()

    # проверка на то что пользователь изменяющий чат имеет админку
    for group_chat_participant in group_chat_participants:
        if group_chat_participant.ChatParticipant.UserId == user_id and group_chat_participant.ChatParticipant.Status == 0:
            return redirect(url_for('group_chat_inf', group_chat_id=group_chat_id))

    # Изменить название
    if request.method == 'POST':
        new_name = request.form['name']
        group_chat.Name = new_name
        session.commit()
        return redirect('/')

    return render_template('/edit_group_chat.html', group_chat=group_chat,
                           group_chat_participants=group_chat_participants)


@app.route('/edit_participants', methods=['POST', 'GET'])
@login_required
def edit_participants():
    user_id = current_user.Id
    if not request.args.get('group_chat_id'):
        return redirect('/')

    # получение данных о чате и о его участниках
    group_chat_id = request.args.get('group_chat_id')
    group_chat = session.query(Chat).filter(Chat.Id == group_chat_id).first()
    group_chat_participants = session.query(ChatParticipant, User).filter(ChatParticipant.ChatId == group_chat_id). \
        join(User, User.Id == ChatParticipant.UserId).order_by(desc(ChatParticipant.Status)).all()

    if request.method == 'POST':
        # Результат поиска
        try:
            search = request.form['search']
            found_users = session.query(User).filter(or_(User.Name == search, User.Login == search)).all()
        except:
            pass
        return render_template('/edit_participants.html', group_chat=group_chat,
                               group_chat_participants=group_chat_participants, found_users=found_users)

    # получение id нового участника
    if request.args.get('new_participant_id'):
        new_participant_id = request.args.get('new_participant_id')
        # проверка того что этого пользователя нет в чате
        for group_chat_participant in group_chat_participants:
            if str(group_chat_participant.ChatParticipant.UserId) == str(new_participant_id):
                return redirect(url_for('edit_participants', group_chat_id=group_chat_id))

        new_group_chat_participant = ChatParticipant(ChatId=group_chat_id, UserId=new_participant_id, Status=0)
        session.add(new_group_chat_participant)
        session.commit()

        # получение обновленного списка участников
        group_chat_participants = session.query(ChatParticipant, User).filter(ChatParticipant.ChatId == group_chat_id). \
            join(User, User.Id == ChatParticipant.UserId).order_by(desc(ChatParticipant.Status)).all()

        # Сообщение о новом пользователе в чат
        new_user = session.query(User).filter(User.Id == new_participant_id).first()
        user_info = "@" + str(new_user.Login) + " : " + str(new_user.Name)
        message_text = "О мой бог, " + user_info + " теперь тоже тут"
        new_content = Content(Text=message_text)
        session.add(new_content)
        session.commit()
        new_message = Message(ChatId=group_chat_id, SenderId=user_id, ContentId=new_content.Id)
        session.add(new_message)
        session.commit()

    return render_template('/edit_participants.html', group_chat=group_chat,
                           group_chat_participants=group_chat_participants)


@app.route('/group_chat_inf', methods=['POST', 'GET'])
@login_required
def group_chat_inf():
    user_id = current_user.Id

    if not request.args.get('group_chat_id'):
        return redirect('/')

    group_chat_id = request.args.get('group_chat_id')
    group_chat_participants = session.query(ChatParticipant, Chat, User). \
        filter(ChatParticipant.ChatId == group_chat_id). \
        join(Chat, Chat.Id == ChatParticipant.ChatId). \
        join(User, User.Id == ChatParticipant.UserId). \
        order_by(desc(ChatParticipant.Status)).all()

    chat_name = ""
    if len(group_chat_participants) > 0:
        chat_name = group_chat_participants[0].Chat.Name

    group_chat_id_for_edit = -1
    # проверка на то что пользователь имеет админку у чата
    for group_chat_participant in group_chat_participants:
        if group_chat_participant.ChatParticipant.UserId == user_id and group_chat_participant.ChatParticipant.Status == 1:
            group_chat_id_for_edit = group_chat_participant.Chat.Id

    return render_template('/group_chat_inf.html', group_chat_participants=group_chat_participants,
                           chat_name=chat_name, group_chat_id_for_edit=group_chat_id_for_edit)


@app.route('/change_status', methods=['POST', 'GET'])
@login_required
def change_status():
    user_id = current_user.Id

    if not (request.args.get('group_chat_id') or request.args.get('user_id')):
        return redirect('/')

    group_chat_id = request.args.get('group_chat_id')
    changed_user_id = request.args.get('user_id')

    group_chat_participants = session.query(ChatParticipant, User).filter(ChatParticipant.ChatId == group_chat_id). \
        join(User, User.Id == ChatParticipant.UserId).all()

    admins_cnt = 0
    for group_chat_participant in group_chat_participants:
        if group_chat_participant.ChatParticipant.Status == 1:
            admins_cnt = admins_cnt + 1
        if group_chat_participant.User.Id == user_id and group_chat_participant.ChatParticipant.Status == 0:
            return redirect('/')

    changed_chat_participant = session.query(ChatParticipant).\
        filter(and_(ChatParticipant.ChatId == group_chat_id, ChatParticipant.UserId == changed_user_id)).first()

    if changed_chat_participant.Status == 1 and admins_cnt == 1:
        return redirect(url_for('edit_participants', group_chat_id=group_chat_id))

    if changed_chat_participant.Status == 1:
        changed_chat_participant.Status = 0
    else:
        changed_chat_participant.Status = 1
    session.commit()

    return redirect(url_for('edit_participants', group_chat_id=group_chat_id))


# api.add_resource(BookResource, '/api/books/<int:book_id>')
# api.add_resource(BooksResource, '/api/books')


if __name__ == "__main__":
    app.run()