FROM python:3.9

ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements-frozen.txt yunodiagnoser.py /app/

RUN pip install --no-cache-dir -r /app/requirements-frozen.txt

CMD ["python3", "/app/yunodiagnoser.py"]
