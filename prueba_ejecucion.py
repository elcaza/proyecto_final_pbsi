import requests
import json

def ejecutar(peticion, headers):
    r = requests.post("http://127.0.0.1:3000/ejecucion",data=json.dumps(peticion), headers=headers)
    print(r.text)

headers = {
    "Content-Type": "application/json; charset=utf-8"
}

peticion = {
    "sitio":"http://altoromutual.com:8080",
    "ejecucion":"",
    "puertos" : { 
		"inicio" : 8070,
		"final" : 8090
    },
    "cookie":"PHDSESSID:jnj8mr8fugu61ma86p9o96frv0",
    "hilos":4,
    "profundidad":2
}

ejecutar(peticion, headers)
