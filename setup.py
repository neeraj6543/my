from setuptools import setup, find_packages

setup(
    name="cyber-ultra-scanner",
    version="1.0",
    packages=find_packages(),
    install_requires=[
        "requests",
        "python-nmap",
        "python-whois"
    ],
    entry_points={
        "console_scripts": [
            "cyber-ultra-scanner=backend.app.main:start"
        ]
    },
)
