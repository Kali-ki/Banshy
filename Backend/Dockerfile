FROM python:3.11.8

# Installation de exiftool
RUN apt-get update && apt-get install -y exiftool

WORKDIR /usr/src/app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

CMD [ "python", "-u", "./Main.py" ]