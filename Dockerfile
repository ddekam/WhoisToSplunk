# Use the same base image as your devcontainer
FROM mcr.microsoft.com/devcontainers/python:1-3.12-bullseye

USER root

# Set working directory
WORKDIR /app

# Copy project files
COPY . /app

# Install dependencies
RUN pip3 install --user -r requirements.txt

# Default command (can be overridden)
CMD ["python3", "main.py"]
