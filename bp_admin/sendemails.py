# -*- coding: utf-8 -*-
from google.appengine.ext import ndb
from bp_includes.lib.basehandler import BaseHandler
from google.appengine.api import taskqueue
import logging
from bp_includes import messages

class AdminSendEmailListHandler(BaseHandler):
    def get(self):
        email_id=self.request.get('email_id')
        params = {
            "recipent": email_id,
        }        
        return self.render_template('admin_send_email.html', **params)
            
    def post(self):
        
        def sendEmail (recipent,subject,body):
            email_url = self.uri_for('taskqueue-send-email')
            taskqueue.add(url=email_url, params={
                'to': recipent,
                'subject': subject,
                'body': body
            })
        
        body = self.request.get('emailbody')
        subject = self.request.get('subject')
        to = self.request.get('recipents')

        try:
            if to == 'ALLUSERS':
                users = self.user_model.query()
                for user in users:
                    sendEmail (user.email,subject,body)
            else:
                for recipents in to.split(','):
                    sendEmail (recipents.strip(),subject,body)
            self.add_message('Emails sent !', 'success')
        
        except Exception as e:
            logging.info('error in form: %s' % e)
            self.add_message('Something went wrong.', 'danger')
            pass
        
        return self.get()
