from setuptools import setup, find_packages

with open("README.md", 'r') as f:
    long_description = f.read()

setup(
   name='cozy-re',
   version='1.5.0',
   description='Python tool for comparing binaries via symbolic execution utilizing the angr framework.',
   long_description=long_description,
   author='Caleb Helbling',
   author_email='chelbling@draper.com',
   packages=find_packages(),
   classifiers=[
      'Programming Language :: Python :: 3',
      'License :: OSI Approved :: MIT License',
      'Operating System :: OS Independent'
   ],
   install_requires=['angr', 'networkx', 'claripy', 'portion', 'textual']
)
