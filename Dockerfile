FROM python:3-alpine
ENV PYTHONUNBUFFERED definitely
ENV TZ Europe/Vienna
WORKDIR /usr/src/app

RUN adduser -s /bin/bash -S netuser && chown netuser:root /usr/src/app
RUN apk add --no-cache --update gcc libc-dev linux-headers git && rm -rf /var/cache/apk/*
RUN apk add alpine-sdk
USER netuser


COPY . .

RUN pip3 install --no-cache-dir -r requirements.txt

CMD ["python", "./main.py"]
