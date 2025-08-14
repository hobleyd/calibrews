FROM python:3

EXPOSE 10444

VOLUME /books
VOLUME /etc/ssl

WORKDIR /opt/calibrews

COPY calibrews.py requirements.txt /opt/calibrews/
RUN pip install --no-cache-dir -r requirements.txt

CMD [ "python3", "/opt/calibrews/calibrews.py" ]

