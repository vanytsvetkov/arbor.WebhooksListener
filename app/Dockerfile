FROM python

# By default, for plotting matplotlib figures it is better to use the Debian-based Python image
#   (faster speed of building and running the container),
#   but for better compactness of the container it is also possible to use the alpine version of the system.

#FROM python:alpine
#RUN apk add --no-cache build-base libressl-dev libffi-dev libxml2-dev libxslt-dev

WORKDIR /app

COPY . /app

RUN pip install --no-cache-dir -r requirements.txt


CMD ["python", "main.py"]
