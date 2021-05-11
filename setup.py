"""Package configuration."""

from setuptools import find_packages, setup


INSTALL_REQUIRES = [
    'pyyaml>=3.11',
]

# Extra dependencies
EXTRAS_REQUIRE = {
    # Test dependencies
    'tests': [
        'bandit',
        'flake8',
        'flake8-import-order',
        'mypy',
        'prospector[with_everything]==1.7.7',
        'pytest-cov',
        'pytest-xdist',
        'pytest',
        'types-PyYAML',
    ],
}

SETUP_REQUIRES = [
    'pytest-runner>=2.7.1',
]

setup(
    author='Giuseppe Lavagetto',
    author_email='joe@wikimedia.org',
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3 :: Only',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: System :: Distributed Computing',
        'Topic :: Software Development :: Libraries',

    ],
    description='Library for interacting with Poolcounter',
    long_description="""This library containse a client for Wikimedia's Poolcounter service.
While the tool was created specifically to be used in MediaWiki, multiple usages have been added
over the years, including from various python softwares. Having a centrally-maintained library
we can use everywhere makes sense.""",
    extras_require=EXTRAS_REQUIRE,
    install_requires=INSTALL_REQUIRES,
    keywords=['wmf', 'poolcounter'],
    license='Apache-2.0',
    name='poolcounter',
    packages=find_packages(exclude=['*.tests', '*.tests.*']),
    setup_requires=SETUP_REQUIRES,
    version='0.0.2',
    url='https://github.com/wikimedia/operations-software-python-poolcounter',
    zip_safe=True,
)
