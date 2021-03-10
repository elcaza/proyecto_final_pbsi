import requests
import json

def ejecutar():
	headers = {
    "Content-Type": "application/json; charset=utf-8"
	}
	r = requests.post("http://127.0.0.1:3000/proximos-escaneos", headers=headers)
	print(r.text)

ejecutar()