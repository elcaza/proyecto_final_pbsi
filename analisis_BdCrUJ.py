
import time
import requests
import json

def ejecutar(peticion, headers):
    r = requests.post("http://127.0.0.1:3000/ejecucion",data=json.dumps(peticion), headers=headers)
    print(r.text)

headers = {
    "Content-Type": "application/json; charset=utf-8"
}

peticion = {
    "sitio":"prueba:8080",
    "ejecucion":1612745454,
    # "sitio":"seguridad.unam.mx"
    # Obtener informacion
    "dnsdumpster" : {
        "revision":True,
        "dns" : True,
        "txt" : True,
        "host" : True,
        "mx" : False
    },
    "robtex" : {
        "revision":True,
        "informacion":True,
        "dns_forward":False,
        "mx_forward":True,
        "host_forward":False,
        "host_reverse":True
    },
    "puertos" : { 
        "revision" : True,
        "opcion" : "rango",
        "rango" : {
            "inicio" : 20,
            "final" : 100
        }
    },
    # Analisis
    "algo":"",
    #Fuzzing
    "cookie":"PHDSESSID:jnj8mr8fugu61ma86p9o96frv0",
    
    #Explotacion
    "profundidad":2
}
fecha_programada = peticion["ejecucion"]
peticion["ejecucion"] = ""
while True:
    fecha_actual = time.time()
    if fecha_actual >= fecha_programada:
        ejecutar(peticion, headers)
        break
    time.sleep(60)
    