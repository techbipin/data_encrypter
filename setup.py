from setuptools import setup, find_packages

readme = ''
try:
    with open('README.md', 'r', encoding='utf-8') as f:
        readme = f.read()
except FileNotFoundError:
    print("Warning: README.rst not found. Skipping long description.")

setup(
    name="data_encrypter",
    version="1.0",
    author="Mr. Bipin Rajesh Tatkare",
    author_email="techbipinrt2526@gmail.com",
    description="A simple data encryption-decryption package for Django models.",
    long_description=readme,
    long_description_content_type='text/markdown',
    url="https://github.com/techbipin/data_encrypter.git",
    packages=find_packages(),
    install_requires=[
        "django==5.0",
    ],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.12',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.11',
)