FROM python:3-alpine
ENV PYTHONUNBUFFERED definitely
ENV TZ Europe/Vienna
WORKDIR /usr/src/app

RUN adduser -s /bin/bash -S netuser && chown netuser:root /usr/src/app
RUN apk add --no-cache --update gcc libc-dev linux-headers git && rm -rf /var/cache/apk/*
USER netuser
COPY requirements.txt ./
RUN pip3 install --no-cache-dir -r requirements.txt

COPY .env.template .env
RUN [ -e "/usr/src/app/.env" ] && echo "Env already exists" || mv .env.template .env
RUN sed -i "s/%SECRET%/$(SECRET)/" .env
RUN sed -i "s/%PW%/$(PW)/" .env
RUN sed -i "s/%TOKEN%/$(TOKEN)/" .env

COPY --from=0 /usr/src/app/.env .
COPY main.py ./
COPY src/ ./src

CMD ["python", "./main.py"]
