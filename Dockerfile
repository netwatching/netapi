FROM python:3-alpine
ENV PYTHONUNBUFFERED definitely
ENV TZ Europe/Vienna
WORKDIR /usr/src/app

COPY requirements.txt ./

RUN apk add --no-cache --update gcc libc-dev linux-headers git && rm -rf /var/cache/apk/*
RUN pip3 install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "./main.py"]
