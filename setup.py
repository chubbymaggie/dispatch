from setuptools import setup

setup(
    name='dispatch',
    version='0.9',
    author='NYU OSIRIS Lab',
    url='https://github.com/isislab/dispatch',
    description='Programmatic disassembly and patching from NYU\'s OSIRIS lab',
    packages=['dispatch', 'dispatch.util', 'dispatch.formats', 'dispatch.analysis'],
    install_requires=[
        'capstone>3.0',
        'keystone-engine',
        'pyelftools',
        'pefile',
        'macholib'
    ]
)
