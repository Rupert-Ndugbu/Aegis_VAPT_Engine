# Use lightweight Python image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy project files
COPY . /app

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose app port
EXPOSE 8080

# Run the app
CMD ["python3", "main/app.py"]
