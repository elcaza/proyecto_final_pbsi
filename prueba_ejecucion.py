import requests
import json

def ejecutar(peticion, headers):
    r = requests.post("http://127.0.0.1:3000/ejecucion",data=json.dumps(peticion), headers=headers)
    print(r.text)

headers = {
    "Content-Type": "application/json; charset=utf-8"
}

peticion = {
    "sitio":"http://localhost/drupal7/",
    #sistemas.acatlan.unam.mx
    "ejecucion":"",
    "puertos" : { 
		"inicio" : 0,
		"final" : 500
    },
    "cookie":"PHDSESSID:jnj8mr8fugu61ma86p9o96frv0",
    "hilos":1,
    "profundidad":2
}

ejecutar(peticion, headers)
