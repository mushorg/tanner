FROM python:3.6-alpine
ADD ./tanner
WORKDIR /tanner
RUN pip3 install -r requirements.txt
CMD ["python", "setup.py"]
