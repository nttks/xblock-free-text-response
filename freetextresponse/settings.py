"""
Settings for freetextresponse xblock
"""

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        # 'NAME': 'intentionally-omitted',
    },
}

INSTALLED_APPS = (
    'django_nose',
    'freetextresponse',
)

TEST_RUNNER = 'django_nose.NoseTestSuiteRunner'

NOSE_ARGS = [
    '--with-coverage',
    '--cover-html',
    '--cover-erase',
]

SECRET_KEY = 'freetextresponse_SECRET_KEY'
