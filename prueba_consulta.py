import requests
import json


def ejecutar_uno():
    headers = {
        "Content-Type": "application/json; charset=utf-8"
    }

    peticion = {}

    r = requests.post("http://127.0.0.1:3000/consulta-volcado",data=json.dumps(peticion), headers=headers)
    print(r.text)

def ejecutar_tres():
    headers = {
        "Content-Type": "application/json; charset=utf-8"
    }

    peticion = {
        "sitio": "http://localhost/drupal7/",
        "fecha":"01/03/2021 17:23:57"
    }
    r = requests.post("http://127.0.0.1:3000/consulta-reporte",data=json.dumps(peticion), headers=headers)
    print(r.text)

ejecutar_uno()
#ejecutar_tres()