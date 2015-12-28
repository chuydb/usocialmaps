# -*- coding: utf-8 -*-
import webapp2, json
from google.appengine.datastore.datastore_query import Cursor
from google.appengine.ext import ndb
from collections import OrderedDict, Counter
from wtforms import fields  
from bp_includes import forms, models, handlers, messages
from bp_includes.lib.basehandler import BaseHandler
from datetime import datetime, date, time, timedelta
import logging


class AdminStatsHandler(BaseHandler):
    def get(self):
        params = {}
        users = self.user_model.query()
        params['sum_users'] = users.count()

        blogs = models.BlogPost.query()
        params['sum_blogs'] = blogs.count()
        return self.render_template('admin_stats.html', **params)

class AdminUserGeoChartHandler(BaseHandler):
    def get(self):
        users = self.user_model.query()
        latlngs = []
        for user in users:
            if user.address is not None:
                if user.address.address_from_coord is not None:
                    latlngs.append(user.address.address_from_coord)

        params = {
            "list_attrs": [('lat', 'lon')],
            "latlngs": latlngs,
        }
        return self.render_template('admin_users_geochart.html', **params)

class EditProfileForm(forms.SettingsProfileForm):
    activated = fields.BooleanField('Activated')

class AdminUserListHandler(BaseHandler):
    def get(self):
        p = self.request.get('p')
        q = self.request.get('q')
        c = self.request.get('c')
        forward = True if p not in ['prev'] else False
        cursor = Cursor(urlsafe=c)

        if q:
            _users = []
            qry = self.user_model.query(ndb.OR(self.user_model.name >= q.lower(),
                                           self.user_model.email >= q.lower(),
                                           self.user_model.username >= q.lower()))
            for _qry in qry:
                if q.lower() in _qry.name.lower() or q.lower() in _qry.email.lower() or q.lower() in _qry.username.lower():
                    _users.append(_qry)
            users = _users
            count = len(users)
        else:
            qry = self.user_model.query()
            count = qry.count()
            PAGE_SIZE = 50
            if forward:
                users, next_cursor, more = qry.order(-self.user_model.last_login).fetch_page(PAGE_SIZE, start_cursor=cursor)
                if next_cursor and more:
                    self.view.next_cursor = next_cursor
                if c:
                    self.view.prev_cursor = cursor.reversed()
            else:
                users, next_cursor, more = qry.order(self.user_model.last_login).fetch_page(PAGE_SIZE, start_cursor=cursor)
                users = list(reversed(users))
                if next_cursor and more:
                    self.view.prev_cursor = next_cursor
                self.view.next_cursor = cursor.reversed()

        def pager_url(p, cursor):
            params = OrderedDict()
            if q:
                params['q'] = q
            if p in ['prev']:
                params['p'] = p
            if cursor:
                params['c'] = cursor.urlsafe()
            return self.uri_for('admin-users-list', **params)

        self.view.pager_url = pager_url
        self.view.q = q

        params = {
            "list_columns": [('username', 'Username | Email'),
                             ('name', 'Name'),
                             ('last_name', 'Last'),
                             ('link_referral', 'Unique Link'),
                             ('key', 'Key'),
                             ('rewards','Rewards'),
                             ('created', 'Created'),
                             ('last_login', 'Last Login')
                             ],
            "users": users,
            "count": count
        }
        return self.render_template('admin_users_list.html', **params)

class AdminUserEditHandler(BaseHandler):
    def get_or_404(self, user_id):
        try:
            user = self.user_model.get_by_id(long(user_id))
            if user:
                return user
        except ValueError:
            pass
        self.abort(404)

    def edit(self, user_id):
        if self.request.POST:
            user = self.get_or_404(user_id)
            if not self.form.validate():
                self.add_message(messages.saving_error, 'danger')
                return self.get()
            name = self.request.get('name')
            last_name = self.request.get('last_name')
            gender = self.request.get('gender')
            phone = self.request.get('phone')
            birth = self.request.get('birth')
            picture = self.request.get('picture') if len(self.request.get('picture'))>1 else None
            activated = True if 'on' in self.request.get('activated') else False

            try:
                user_info = self.user_model.get_by_id(long(user_id))
                user_info.name = name
                user_info.activated = activated
                user_info.last_name = last_name
                if (len(birth) > 9):
                    user_info.birth = date(int(birth[:4]), int(birth[5:7]), int(birth[8:]))
                if 'male' in gender:
                    user_info.gender = gender
                user_info.phone = phone
                if picture is not None:
                    user_info.picture = images.resize(picture, width=180, height=180, crop_to_fit=True, quality=100)
                user_info.put()
                self.add_message(messages.saving_success, 'success')
                return self.redirect_to("admin-user-edit", user_id=user_id)
                

            except (AttributeError, KeyError, ValueError), e:
                logging.error('Error updating profile: %s ' % e)
                self.add_message(messages.saving_error, 'danger')
                return self.redirect_to("admin-user-edit", user_id=user_id)
        else:
            user = self.get_or_404(user_id)
            self.form.process(obj=user)

        params = {
            'user': user
        }
        return self.render_template('admin_user_edit.html', **params)

    @webapp2.cached_property
    def form(self):
        f = EditProfileForm(self)
        return f

class AdminExportUsers(BaseHandler):
    
    def get(self):
        _users= []
        users = self.user_model.query()
        for user in users:
                _users.append({'username': user.username, 'name': user.name, 'email': user.email, 'last_login': user.last_login})
                                    
        self.response.headers.add_header("Access-Control-Allow-Origin", "*")
        self.response.headers['Content-Type'] = 'application/json'
        self.response.write(json.dumps(_users))
