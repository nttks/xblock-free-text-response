import json
from setuptools import setup
from setuptools.command.test import test as TestCommand


class Tox(TestCommand):
    user_options = [('tox-args=', 'a', 'Arguments to pass to tox')]

    def initialize_options(self):
        TestCommand.initialize_options(self)
        self.tox_args = None

    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        # import here, cause outside the eggs aren't loaded
        import tox
        import shlex
        args = self.tox_args
        if args:
            args = shlex.split(self.tox_args)
        errno = tox.cmdline(args=args)
        sys.exit(errno)

setup(
    name="xblock-free-text-response",
    version="0.4.0",
    description="Enables instructors to create questions with free-text responses.",
    license='AGPL-3.0',
    packages=[
        'freetextresponse',
    ],
    install_requires=[
        'coverage',
        'ddt',
        'django<2.0',
        'django_nose',
        'edx-opaque-keys',
        'enum34',
        'mock',
        'mako',
        'XBlock',
        'xblock-utils',
    ],
    entry_points={
        'xblock.v1': [
            'freetextresponse = freetextresponse:FreeTextResponse',
        ],
    },
    package_dir={
        'freetextresponse': 'freetextresponse',
    },
    package_data={
        "freetextresponse": [
            'public/*',
            'templates/*',
        ],
    },
    classifiers=[
        # https://pypi.python.org/pypi?%3Aaction=list_classifiers
        'Intended Audience :: Developers',
        'Intended Audience :: Education',
        'License :: OSI Approved :: GNU Affero General Public License v3',
        'Operating System :: OS Independent',
        'Programming Language :: JavaScript',
        'Programming Language :: Python',
        'Topic :: Education',
        'Topic :: Internet :: WWW/HTTP',
    ],
)
