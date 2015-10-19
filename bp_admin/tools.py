# -*- coding: utf-8 -*-
from bp_includes.lib.basehandler import BaseHandler


class AdminCSSHandler(BaseHandler):
    def get(self):
        params = {}
        return self.render_template('admin_tools_css.html', **params)

class AdminIconsHandler(BaseHandler):
    def get(self):
        params = {}
        return self.render_template('admin_tools_icons.html', **params)

class AdminMediaHandler(BaseHandler):
    def get(self):
        params = {}
        return self.render_template('admin_tools_media.html', **params)
