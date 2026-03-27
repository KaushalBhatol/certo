FROM python:3.12-slim

WORKDIR /app

# Install dependencies first (layer cache friendly)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create a non-root user and own the app directory
RUN adduser --disabled-password --gecos "" certouser \
 && mkdir -p data \
 && chown -R certouser:certouser /app

USER certouser

EXPOSE 8080

ENTRYPOINT ["sh", "docker-entrypoint.sh"]
