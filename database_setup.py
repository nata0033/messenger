from sqlalchemy import *
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy_serializer import SerializerMixin
from flask_login import UserMixin
from datetime import datetime


# создание экземпляра declarative_base
Base = declarative_base()


class User(Base, UserMixin, SerializerMixin):
    __tablename__ = 'user'

    Id = Column(Integer, primary_key=True)
    Name = Column(String(300), nullable=False)
    Photo = Column(String(300), default="/static/images/icon.jpg")
    Login = Column(String(300), unique=True, nullable=False)
    Password = Column(String(300), nullable=False)
    ChatParticipants = relationship('ChatParticipant', backref='user', lazy=True)
    Messages = relationship('Message', backref='user', lazy=True)

    def get_id(self):
        return self.Id


class Chat(Base):
    __tablename__ = 'chat'

    Id = Column(Integer, primary_key=True)
    Name = Column(String(300), nullable=False, default="")
    Type = Column(Integer, nullable=False, default=0)  # 0-личная переписка 1-общий чат
    Date = Column(DateTime, default=datetime.utcnow, nullable=False)
    Messages = relationship('Message', backref='chat', lazy=True)
    ChatParticipants = relationship('ChatParticipant', backref='chat', lazy=True)


class Message(Base):
    __tablename__ = 'message'

    Id = Column(Integer, primary_key=True)
    Date = Column(DateTime, default=datetime.utcnow, nullable=False)
    Status = Column(Integer, nullable=False, default=0)  # 0-не прочитано 1-прочитанно
    SenderId = Column(Integer, ForeignKey('user.Id'), nullable=False)
    ChatId = Column(Integer, ForeignKey('chat.Id'), nullable=False)
    ContentId = Column(Integer, ForeignKey('content.Id'), nullable=False)


class Content(Base):
    __tablename__ = 'content'

    Id = Column(Integer, primary_key=True)
    Text = Column(Text, nullable=False, default="")
    Photo = Column(String(300), nullable=False, default="")
    Messages = relationship('Message', backref='content', lazy=True)


class ChatParticipant(Base):
    __tablename__ = 'chat_participant'

    Id = Column(Integer, primary_key=True)
    Status = Column(Integer, nullable=False, default=0)  # 0-участник, 1-администратор
    UserId = Column(Integer, ForeignKey('user.Id'), nullable=False)
    ChatId = Column(Integer, ForeignKey('chat.Id'), nullable=False)


engine = create_engine('sqlite:///messenger.db')
Base.metadata.create_all(engine)
