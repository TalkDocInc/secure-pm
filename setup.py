from setuptools import setup, find_packages

setup(
    name="secure-pm",
    version="0.1.1",
    description="Secure Package Manager - AI Audited Dependency Installation",
    author="Open Source Community",
    packages=find_packages(),
    install_requires=[
        "requests>=2.30.0",
        "openai>=1.0.0",
        "rich>=13.0.0",
        "python-dotenv>=1.0.0",
    ],
    entry_points={
        "console_scripts": [
            "secure-pm=talkdoc_secure_pm.cli:main",
        ],
    },
    python_requires=">=3.12",
)
