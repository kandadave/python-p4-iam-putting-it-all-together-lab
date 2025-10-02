#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        data = request.get_json()
        if not data.get('username'):
            return {'errors': ['Username is required']}, 422
        if not data.get('password'):
            return {'errors': ['Password is required']}, 422
        try:
            new_user = User(
                username=data['username'],
                image_url=data.get('image_url', ''),
                bio=data.get('bio', '')
            )
            new_user.password = data['password']  # Uses setter to hash password
            db.session.add(new_user)
            db.session.commit()
            session['user_id'] = new_user.id
            return {
                'id': new_user.id,
                'username': new_user.username,
                'image_url': new_user.image_url,
                'bio': new_user.bio
            }, 201
        except IntegrityError:
            db.session.rollback()
            return {'errors': ['Username already exists']}, 422
        except ValueError as e:
            return {'errors': [str(e)]}, 422

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if user_id:
            user = db.session.get(User, user_id)
            if user:
                return {
                    'id': user.id,
                    'username': user.username,
                    'image_url': user.image_url,
                    'bio': user.bio
                }, 200
        return {'error': 'Not logged in'}, 401

class Login(Resource):
    def post(self):
        data = request.get_json()
        if not data.get('username') or not data.get('password'):
            return {'error': 'Username and password are required'}, 401
        user = User.query.filter_by(username=data['username']).first()
        print(f"Login attempt for {data['username']}, password: {data['password']}, user: {user}, auth: {user.authenticate(data['password']) if user else None}")
        if user and user.authenticate(data['password']):
            session['user_id'] = user.id
            print(f"Session set: user_id={session['user_id']}")
            return {
                'id': user.id,
                'username': user.username,
                'image_url': user.image_url,
                'bio': user.bio
            }, 200
        return {'error': 'Invalid credentials'}, 401

class Logout(Resource):
    def delete(self):
        if session.get('user_id'):
            session.pop('user_id')
            return '', 204
        return {'error': 'Not logged in'}, 401

class RecipeIndex(Resource):
    def get(self):
        if not session.get('user_id'):
            print(f"No session: user_id={session.get('user_id')}")
            return {'error': 'Not authorized'}, 401
        recipes = Recipe.query.all()
        recipe_list = [
            {
                **recipe.to_dict(only=('id', 'title', 'instructions', 'minutes_to_complete')),
                'user': recipe.user.to_dict(only=('id', 'username', 'image_url', 'bio'))
            }
            for recipe in recipes
        ]
        return recipe_list, 200

    def post(self):
        if not session.get('user_id'):
            return {'error': 'Not authorized'}, 401
        data = request.get_json()
        try:
            new_recipe = Recipe(
                title=data['title'],
                instructions=data['instructions'],
                minutes_to_complete=data['minutes_to_complete'],
                user_id=session['user_id']
            )
            db.session.add(new_recipe)
            db.session.commit()
            response = {
                **new_recipe.to_dict(only=('id', 'title', 'instructions', 'minutes_to_complete')),
                'user': new_recipe.user.to_dict(only=('id', 'username', 'image_url', 'bio'))
            }
            return response, 201
        except ValueError as e:
            return {'errors': [str(e)]}, 422

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')

if __name__ == '__main__':
    app.run(port=5555, debug=True)