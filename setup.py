from distutils.core import setup
from pyspresso.__init__ import __version__

setup(
    name="pyspresso",
    version=__version__,
    author="Jason Geffner",
    author_email="jason@malwareanalysis.com",
    url="https://github.com/CrowdStrike/pyspresso/",
    description="Python-based framework for debugging Java",
    long_description="Python-based framework for debugging Java",
    packages=["pyspresso",],
    platforms="Android, Linux, MacOS, Windows",
    license="GNU General Public License v3 or later (GPLv3+)",
    classifiers=["Development Status :: 3 - Alpha",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
        "Natural Language :: English",
        "Operating System :: Android",
        "Operating System :: MacOS",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python",
        "Topic :: Software Development :: Debuggers"],
)