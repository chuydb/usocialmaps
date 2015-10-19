"""
This configuration file loads environment's specific config settings for the application.
It takes precedence over the config located in the boilerplate package.
"""

import os


if "SERVER_SOFTWARE" in os.environ:
    if os.environ['SERVER_SOFTWARE'].startswith('Dev'):
		from localhost import config
    elif os.environ['SERVER_SOFTWARE'].startswith('Google'):
			from production import config
    else:
		raise ValueError("Environment undetected")
else:
	from testing import config