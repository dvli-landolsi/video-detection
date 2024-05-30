FROM python:3.9

# Install system dependencies first
RUN apt-get update && apt-get install -y \
    libgl1-mesa-glx \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY ./requirements.txt /app/requirements.txt

# Use verbose mode to get more detailed logs during pip install
RUN pip install --no-cache-dir --upgrade -r /app/requirements.txt -v

COPY ./src /app/src

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
