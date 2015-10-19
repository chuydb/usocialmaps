from webapp2_extras.routes import RedirectRoute
import users
import admin
import blog
import logsemails
import logsvisits
import crontasks
import tools
import sendemails


_routes = [
    RedirectRoute('/admin/', users.AdminStatsHandler, name='admin', strict_slash=True),
    RedirectRoute('/admin/geo/', users.AdminUserGeoChartHandler, name='admin-users-geochart', strict_slash=True),
    RedirectRoute('/admin/blog/', blog.AdminBlogHandler, name='admin-blog', strict_slash=True),
    RedirectRoute('/admin/blog/<post_id>/', blog.AdminBlogEditHandler, name='admin-blog-edit', strict_slash=True),
    RedirectRoute('/admin/blog/upload/<post_id>/', blog.AdminBlogUploadHandler, name='admin-blog-upload', strict_slash=True),
    RedirectRoute('/admin/users/', users.AdminUserListHandler, name='admin-users-list', strict_slash=True),
    RedirectRoute('/admin/users/export/', users.AdminExportUsers, name='admin-export-users', strict_slash=True),
    RedirectRoute('/admin/users/<user_id>/', users.AdminUserEditHandler, name='admin-user-edit', strict_slash=True, handler_method='edit'),
    RedirectRoute('/admin/logs/emails/', logsemails.AdminLogsEmailsHandler, name='admin-logs-emails', strict_slash=True),
    RedirectRoute('/admin/logs/emails/<email_id>/', logsemails.AdminLogsEmailViewHandler, name='admin-logs-email-view', strict_slash=True),
    RedirectRoute('/admin/logs/visits/', logsvisits.AdminLogsVisitsHandler, name='admin-logs-visits', strict_slash=True),
    RedirectRoute('/admin/send/email/', sendemails.AdminSendEmailListHandler, name='admin-send-email', strict_slash=True),
    RedirectRoute('/admin/logout/', admin.AdminLogoutHandler, name='admin-logout', strict_slash=True),
    RedirectRoute('/admin/tools/css/', tools.AdminCSSHandler, name='admin-tools-css', strict_slash=True),
    RedirectRoute('/admin/tools/icons/', tools.AdminIconsHandler, name='admin-tools-icons', strict_slash=True),
    RedirectRoute('/admin/tools/media/', tools.AdminMediaHandler, name='admin-tools-media', strict_slash=True),
    RedirectRoute('/crontasks/cleanuptokens/', crontasks.AdminCleanupTokensHandler, name='admin-crontasks-cleanuptokens', strict_slash=True),
]

def get_routes():
    return _routes

def add_routes(app):
    for r in _routes:
        app.router.add(r)
