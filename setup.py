from setuptools import setup


setup(
    name = "pyreadelf",
    packages=['pyreadelf'],
    author = "Ahmed Alsawi",
    author_email = "",
    description = (""),
    license = "GPLv3",
    entry_points={
        'console_scripts': [
            'pyreadelf=pyreadelf.main:main'
        ]
    }
)

