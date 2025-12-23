# 1. Base image set karein (Python 3.11 stable hai)
FROM python:3.11-slim

# 2. System dependencies install karein (dlib aur opencv ke liye zaroori)
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    libopenblas-dev \
    liblapack-dev \
    libx11-dev \
    libgtk-3-dev \
    libgl1-mesa-glx \
    && rm -rf /var/lib/apt/lists/*

# 3. App folder banayein
WORKDIR /app

# 4. Requirements file copy karke install karein
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip setuptools wheel
RUN pip install --no-cache-dir -r requirements.txt

# 5. Baaki saara code copy karein
COPY . .

# 6. Port define karein
EXPOSE 5000

# 7. App start karne ki command
CMD ["python", "start_production.py"]
