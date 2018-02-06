import os
import sys
from sqlalchemy import Column,ForeignKey,Integer,String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()

class User(Base):
    __tablename__ = 'user'

    userName = Column(String(80),primary_key=True)
    userPassword = Column(String(250))
    userEmail = Column(String(250))
    


class Category(Base):
    __tablename__='category'

    id = Column(Integer,primary_key=True)
    catName = Column(String(80),nullable=False)
    userName = Column(String(80),ForeignKey('user.userName'))
    user = relationship(User)

    @property
    def serialize(self):
        return{
            'catName'       :   self.catName,
            'id'            :   self.id,
            }




class Item(Base):
    __tablename__ = 'sub_category'

    itemName = Column(String(80),nullable=False)
    id = Column(Integer,primary_key=True)
    description = Column(String(250))
    category_id = Column(Integer,ForeignKey('category.id'))
    category = relationship(Category)
    userName = Column(String(80),ForeignKey('user.userName'))
    user = relationship(User)
    
    @property
    def serialize(self):
        return{
                'cat_id'        :   self.category_id,
                'id'            :   self.id,
                'ItemName'      :    self.itemName,
                'description'   :   self.description,
            }


engine = create_engine('sqlite:///ItemCatlog.db')

Base.metadata.create_all(engine)

