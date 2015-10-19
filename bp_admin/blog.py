# -*- coding: utf-8 -*-
import webapp2, json
from google.appengine.datastore.datastore_query import Cursor
from google.appengine.ext import ndb, blobstore
from google.appengine.ext.webapp import blobstore_handlers
from collections import OrderedDict, Counter
from wtforms import fields  
from bp_includes import forms, models, handlers, messages
from bp_includes.lib.basehandler import BaseHandler
from datetime import datetime, date, time, timedelta
import logging


class AdminBlogHandler(BaseHandler):
   def get(self):
        p = self.request.get('p')
        q = self.request.get('q')
        c = self.request.get('c')
        forward = True if p not in ['prev'] else False
        cursor = Cursor(urlsafe=c)

        if q:
            qry = models.BlogPost.query(ndb.OR(models.BlogPost.title == q.lower(),
                                            models.BlogPost.author == q.lower(),
                                            models.BlogPost.category.IN(q.lower().split(','))))
            count = qry.count()
            blogs = qry
        else:
            qry = models.BlogPost.query()
            count = qry.count()
            PAGE_SIZE = 50
            if forward:
                blogs, next_cursor, more = qry.order(-models.BlogPost.updated).fetch_page(PAGE_SIZE, start_cursor=cursor)
                if next_cursor and more:
                    self.view.next_cursor = next_cursor
                if c:
                    self.view.prev_cursor = cursor.reversed()
            else:
                blogs, next_cursor, more = qry.order(models.BlogPost.updated).fetch_page(PAGE_SIZE, start_cursor=cursor)
                blogs = list(reversed(blogs))
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
            return self.uri_for('admin-blog', **params)

        self.view.pager_url = pager_url
        self.view.q = q

        params = {
            "list_columns": [('title', 'Title'),
                             ('author', 'Author'),
                             ('created', 'Created'),
                             ('updated', 'Updated'),
                             ('category', 'Categories')],
            "blogs": blogs,
            "count": count
        }
        return self.render_template('admin_blog.html', **params)

class AdminBlogEditHandler(BaseHandler):
    def get(self, post_id):
        params = {}
        params['blob_key'] = ''
        params['title'] = ''
        params['subtitle'] = ''
        params['author'] = ''
        params['brief'] = ''
        params['content'] = ''
        params['category'] = ''
        params['post_id'] = post_id if len(str(post_id)) > 0 else 1
        if post_id != 1:
            blog = models.BlogPost.get_by_id(long(post_id))
            if blog is not None:
                params['blob_key'] = blog.blob_key
                params['title'] = blog.title
                params['subtitle'] = blog.subtitle
                params['author'] = blog.author
                params['brief'] = blog.brief
                params['content'] = blog.content
                params['category'] = blog.category
        return self.render_template('admin_blog_edit.html', **params)

    def post(self, post_id):
        if post_id == '1':
            blog = models.BlogPost()
            blog.title = self.request.get('title')
            blog.subtitle = self.request.get('subtitle')
            blog.author = self.request.get('author')
            blog.brief = self.request.get('brief')
            blog.content = self.request.get('content')
            blog.category = self.request.get('category').split(',')
            blog.put()            
        else:
            blog = models.BlogPost.get_by_id(long(post_id))
            if blog is not None:
                blog.title = self.request.get('title')
                blog.subtitle = self.request.get('subtitle')
                blog.author = self.request.get('author')
                blog.brief = self.request.get('brief')
                blog.content = self.request.get('content')
                blog.category = self.request.get('category').split(',')
                blog.put()

        #re-post to blobstore, documented at: https://code.google.com/p/googleappengine/issues/detail?id=2749#makechanges
        from google.appengine.api import urlfetch
        from poster.encode import multipart_encode, MultipartParam
        payload = {}
        file_data = self.request.POST['file']
        payload['file'] = MultipartParam('file', filename=file_data.filename,
                                              filetype=file_data.type,
                                              fileobj=file_data.file)
        data,headers= multipart_encode(payload)
        upload_url = blobstore.create_upload_url('/admin/blog/upload/%s/' % blog.key.id())        
        t = urlfetch.fetch(url=upload_url, payload="".join(data), method=urlfetch.POST, headers=headers)

        #output toast message
        if t.content == 'success':
            self.add_message(messages.saving_success, 'success')
            return self.redirect_to('admin-blog')
        else:
            self.add_message(messages.saving_error, 'danger')
            return self.get(post_id = blog.key.id())

class AdminBlogUploadHandler(blobstore_handlers.BlobstoreUploadHandler):
    def post(self, post_id):
        try:
            blog = models.BlogPost.get_by_id(long(post_id))
            try:
                blobstore.delete(blog.blob_key)
            except:
                pass
            upload = self.get_uploads()[0]
            blog.blob_key = upload.key()                                               
            blog.put()
            self.response.headers['Content-Type'] = 'text/plain'
            self.response.out.write('success')
        except Exception as e:
            logging.error('something went wrong: %s' % e)
            self.response.headers['Content-Type'] = 'text/plain'
            self.response.out.write('error')

