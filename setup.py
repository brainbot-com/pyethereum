
from setuptools import setup, find_packages

console_scripts = ['eth=pyethereum.eth:main']

setup(name="pyethereum",
      packages=find_packages("."),
      install_requires=['leveldb', 'pybitcointools', 'pysha3'])
