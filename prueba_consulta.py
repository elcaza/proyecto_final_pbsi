import requests
import json


def ejecutar_uno():
    headers = {
        "Content-Type": "application/json; charset=utf-8"
    }

    peticion = {}

    r = requests.post("http://127.0.0.1:3000/consulta-buscar",data=json.dumps(peticion), headers=headers)
    print(r.text)

def ejecutar_dos():
    headers = {
        "Content-Type": "application/json; charset=utf-8"
    }

    peticion = {
        "sitio":"http://altoromutual.com:8080",
        "fecha":"16/02/2021 18:26:24"
    }
    r = requests.post("http://127.0.0.1:3000/consulta-analisis",data=json.dumps(peticion), headers=headers)
    print(r.text)

def ejecutar_tres():
    headers = {
        "Content-Type": "application/json; charset=utf-8"
    }

    peticion = {
        "sitio":"http://altoromutual.com:8080",
        "fecha":"16/02/2021 18:26:24"
    }
    r = requests.post("http://127.0.0.1:3000/reporte",data=json.dumps(peticion), headers=headers)
    print(r.text)

#ejecutar_uno()
#ejecutar_dos()
ejecutar_tres()