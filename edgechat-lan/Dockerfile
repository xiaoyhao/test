FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt cryptography
COPY app.py ./
COPY static ./static
ENV EDGECHAT_DATA=/app/data
EXPOSE 8790
VOLUME ["/app/data"]
CMD ["python3", "app.py"]
