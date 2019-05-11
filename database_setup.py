# Functions and variables
import os
import sys
# Come in handy when writing mapper code
from sqlalchemy import Column, ForeignKey, Integer, String
# Will use in configuration and class code.
from sqlalchemy.ext.declarative import declarative_base
# Create foreign key relationship, for mapper
from sqlalchemy.orm import relationship
# Use in config code
from sqlalchemy import create_engine
# Used to create secret_key
import random
import string

# make instance of declarative_base() class
# Will let sqlalchemy know that classes are special SQL alchemy classes
# that correspond to tables in database.
Base = declarative_base()

# Secret key generated to use to sign tokens.
secret_key = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))


# CLASS
# Classes that represent each table
class User(Base):
	# TABLE
	# Represenation of our table inside the database
	__tablename__ = 'User'
	# MAPPER
	# email, username, and password columns with 80 character max, required
	# id column, primary key
	id = Column(
		Integer,
		primary_key = True
		)
	email = Column(
		String(80),
		unique = True,
		nullable = False
		)
	username = Column(
		String(80),
		unique = True,
		nullable = False
		)
	password = Column(
		String(80),
		nullable = False
		)
	# Decorator property to serialize data from the database
	@property
	def serialize(self):
		# Returns object data in an easily serializeable format
		return {
			'id' : self.id,
			'email' : self.email,
			'username' : self.username,
			'password' : self.password
		}

class Category(Base):
	# TABLE
	# Represenation of our table inside the database
	__tablename__ = 'Category'
	# MAPPER
	id = Column(
		Integer,
		primary_key = True
		)
	user_id = Column(
		Integer,
		ForeignKey('User.id'),
		nullable = False
		)
	user = relationship(User)
	name = Column(
		String(80),
		nullable = False
		)
	# Decorator property to serialize data from the database
	@property
	def serialize(self):
		# Returns object data in an easily serializeable format
		return {
			'id': self.id,
			'name': self.name
		} 

class Item(Base):
	# TABLE
	# Represenation of our table inside the database
	__tablename__ = 'Item'
	# MAPPER
	id = Column(
		Integer,
		primary_key = True
		)
	user_id = Column(
		Integer,
		ForeignKey('User.id'),
		nullable = False
		)
	user = relationship(User)
	category_id = Column(
		Integer,
		ForeignKey('Category.id')	
		)
	category = relationship(
		Category, 
		single_parent = True,
		cascade='all, delete-orphan'
		)
	name = Column(
		String(80),
		nullable = False
		)
	description = Column(
		String(80),
		nullable = False
		)
	# Decorator property to serialize data from the database
	@property
	def serialize(self):
		# Returns object data in an easily serializeable format
		return {
			'category_id': self.category_id,
			'name': self.name,
			'description': self.description
		} 




#####INSERT AT END OF FILE######

# Create instance of create_engine class
# and point to database we will use
# sqlite will create new engine file below
engine = create_engine(
	'sqlite:///catalog.db')

# Goes into database and adds classes that we will soon create
# as new tables in database
Base.metadata.create_all(engine)