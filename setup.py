import json
from setuptools import setup, find_namespace_packages

with open('netconfdriver/pkg_info.json') as fp:
    _pkg_info = json.load(fp)

with open("DESCRIPTION.md", "r") as description_file:
    long_description = description_file.read()

setup(
    name='netconfdriver',
    version=_pkg_info['version'],
    description='None',
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_namespace_packages(include=['netconfdriver*','ncclient*']),
    include_package_data=True,
    install_requires=[
        'gunicorn==22.0.0',
        'uvicorn==0.29.0',
        'lxml==4.9.1',
        'paramiko==3.4.0',
        'six==1.16.0',
        'ignition-framework=={0}'.format(_pkg_info['ignition-version'])
    ],
    entry_points='''
        [console_scripts]
        netconfdriver-dev=netconfdriver.__main__:main
    '''
)
