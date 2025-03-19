from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="icespire_scanner",
    version="1.0.0",
    author="rinnchan99",
    author_email="your.email@example.com",
    description="A simple network scanner tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/icespire_scanner",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
    install_requires=[],  # Dependencies (if any)
    entry_points={
        "console_scripts": [
            "icespire=icespire_scanner.scanner:scan",  # CLI command
        ],
    },
)