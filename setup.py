from setuptools import setup, find_packages  # type: ignore[import-untyped]

setup(
    name="altcha",
    version="2.0.0b1",
    description="A library for creating and verifying challenges for ALTCHA.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Daniel Regeci",
    author_email="536331+ovx@users.noreply.github.com",
    url="https://github.com/altcha-org/altcha-lib-py",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.9",
    install_requires=[
        # Add any dependencies here
    ],
)
