FROM python
WORKDIR /app
ENV CLIENT_ID $CLIENT_ID
COPY requirements.txt ./
RUN pip install -r requirements.txt
COPY . .
EXPOSE 8000
#CMD [ "flask", "run","--host","0.0.0.0","--port","8000"]
CMD [ "python", "app.py", "--client", "$CLIENT_ID"]
