# build container
FROM python:3-alpine as netapi-config
WORKDIR /usr/src/app
RUN apk add --no-cache --update gcc libc-dev linux-headers alpine-sdk python3-dev && rm -rf /var/cache/apk/*
RUN adduser -s /bin/bash -S netapi
USER netapi
COPY requirements.txt ./
RUN pip3 install --no-cache-dir -r requirements.txt
# main container
FROM python:3-alpine as netapi
ENV PYTHONUNBUFFERED definitely
ENV TZ Europe/Vienna
WORKDIR /usr/src/app
RUN adduser -s /bin/bash -S netapi && chown netapi:root /usr/src/app
COPY --from=0 /home/netapi/.local/lib/python3.*/site-packages /home/netapi/.local/lib/python/site-packages
RUN mkdir --parents  /home/netapi/.local/lib/python$(python --version | sed -e 's/[^0-9.]//g' | cut -f1,2 -d'.'); \
        mv /home/netapi/.local/lib/python/site-packages /home/netapi/.local/lib/python$(python --version | sed -e 's/[^0-9.]//g' | cut -f1,2 -d'.')/site-packages;\
        rmdir /home/netapi/.local/lib/python
USER netapi
COPY main.py ./
COPY src/ ./src
COPY ssl/ ./ssl
CMD ["python", "main.py"]