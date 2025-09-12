from setuptools import setup, find_packages

setup(
    name="wipeit",
    version="0.1.0",
    packages=find_packages(exclude=['tests*', 'docs*']),
    install_requires=[
        "cryptography>=3.4",
        "pyyaml>=5.4",
        "click>=8.0",
        "tqdm>=4.0.0",
        "psutil>=5.9.0",
    ],
    entry_points={
        'console_scripts': [
            'wipeit=wipeit.cli.main:main',
        ],
    },
    python_requires='>=3.8',
)
