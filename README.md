# jwt-jku-attack
Simple example of JWT attack by abusing the jku field

This project contains two services:
- Auth Service (port 5000): allows user to register an account and login to retrieve a JWT token.
- Greeting Service (port 6000): allows user to get cool greetings, with a secret greeting only for admins.
The user must supply a valid JWT token to be able to access the Greeting Service

## Setup

```bash
# start Auth Service
cd auth_service
python3 app.py

# start Greeting Service
cd greeting_service
python3 app.py
```

## Normal flow

```bash
curl -X POST http://localhost:5000/register -H "Content-Type: application/json" -d '{"username":"me","password":"p4ssw0rd"}'
curl -X POST http://localhost:5000/login -H "Content-Type: application/json" -d '{"username":"me","password":"p4ssw0rd"}'
# replace 'TOKEN' in below command with printed token from previous command
curl http://localhost:6000/greeting -H 'Authorization:TOKEN'
curl http://localhost:6000/secret_greeting -H 'Authorization:TOKEN'
```

## Exploit

```bash
# start evil server
curl -X POST http://localhost:5000/register -H "Content-Type: application/json" -d '{"username":"me","password":"p4ssw0rd"}'
cd exploit
python3 evil_server.py

# run exploit
cd exploit
python3 exploit.py
# replace 'TOKEN' in below command with printed token from previous command
curl http://localhost:6000/secret_greeting -H 'Authorization:TOKEN'
```
