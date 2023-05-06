import pathlib
from setuptools import setup

# The directory containing this file
HERE = pathlib.Path(__file__).parent

# The text of the README file
README = (HERE / "README.md").read_text()

# This call to setup() does all the work
setup(
    name="simple_snmp",
    version="1.0.0",
    description="SNMP Client module for easier use",
    long_description=README,
    long_description_content_type="text/markdown",
    url="http://git.frontiir.net/oss-dev/simple_snmp",
    author="Kaung Yar Zar",
    author_email="kaung.yarzar@frontiir.net",
    license="",
    packages=["simple_snmp"],
    include_package_data=False,
    install_requires=[
        "netaddr==0.7.19",
        "ply==3.11",
        "pyasn1==0.4.8",
        "pycryptodomex==3.10.1",
        "pysmi==0.3.4",
        "pysnmp==4.4.9",

    ]
)
