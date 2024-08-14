FROM python

ENV PYTHONUNBUFFERED=0
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt

CMD ["python", "updateroute.py"]