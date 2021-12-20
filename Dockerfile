FROM python:3.9-slim-buster
ENV PYTHONUNBUFFERED definitely
ENV TZ Europe/Vienna
WORKDIR /usr/src/app

COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "./main.py"]
