from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name="dj-data-secure",
    version="1.0",
    author="Mr. Bipin Rajesh Tatkare",
    author_email="techbipinrt2526@gmail.com",
    description="A simple data encryption-decryption package for Django models.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/data_encrypter",
    packages=find_packages(),
    install_requires=[
        "django==5.0",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.11',
)