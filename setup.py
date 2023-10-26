from distutils.core import setup
import setuptools

setup(
    name='octodns-custom-providers',
    version='0.7.0',
    author="Jonas Gunz",
    author_mail="himself@jonasgunz.de",
    description="Custom sources for OctoDNS",
    packages=setuptools.find_packages(),
    install_requires=[
        "octodns",
        "phpipam-api>=1.0.0",
        "dnspython>=2.1.0"
    ],
    license='MIT',
    long_description=open('README.md').read(),
    long_description_content_type="text/markdown",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)

