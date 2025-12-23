# 1. Base image: Python 3.11 use kar rahe hain jo dlib ke liye stable hai
FROM python:3.11-slim

# 2. System dependencies: dlib, face_recognition aur opencv ke liye zaroori
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    libopenblas-dev \
    liblapack-dev \
    libx11-dev \
    libgtk-3-dev \
    libgl1 \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# 3. Working directory set karein
WORKDIR /app

# 4. Requirements file copy karein
COPY requirements.txt .

# 5. Pip aur basic tools update karein
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

# 6. Sari libraries install karein (Isme dlib build hone mein time lagega)
RUN pip install --no-cache-dir -r requirements.txt

# 7. Baaki saara project code copy karein
COPY . .

# 8. Flask/Gunicorn ke liye port 5000 expose karein
EXPOSE 5000

# 9. Startup command: Aapka script gunicorn launch karega
CMD ["python", "start_production.py"]
