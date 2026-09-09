# Official lightweight Python image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy the dependencies file and install them
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy Python script into container
COPY ioc_analyzer.py .

# Set entrypoint
ENTRYPOINT ["python3", "ioc_analyzer.py"]
