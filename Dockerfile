FROM python:3.12-slim

WORKDIR /app

# Install Tesseract OCR and required system packages
RUN apt-get update && apt-get install -y \
    tesseract-ocr \
    libtesseract-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create upload directory
RUN mkdir -p Uploads

# Render uses port 10000
EXPOSE 10000

# Start Flask using Gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:10000", "app:app"]