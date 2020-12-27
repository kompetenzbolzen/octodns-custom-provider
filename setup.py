from distutils.core import setup
import setuptools

setup(
    name='octodns-custom-providers',
    version='0.0.0-dev',
    author="Jonas Gunz",
    description="Custom sources for OctoDNS",
    packages=setuptools.find_packages(),
    install_requires=[
        "octodns",
        "phpipam"
    ],
    license='MIT',
    long_description=open('README.md').read(),
    long_description_content_type="text/markdown",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT",
        "Operating System :: OS Independent",
    ],
)

