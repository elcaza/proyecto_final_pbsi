
import time
import requests
import json

def ejecutar(peticion, headers):
    r = requests.post("http://127.0.0.1:3000/ejecucion",data=json.dumps(peticion), headers=headers)
    print(r.text)

headers = {"Content-Type": "application/json; charset=utf-8"}

peticion = {'sitio': 'http://altoromutual.com:8080/feedback.jsp', 'fecha': '2021-04-07', 'file': {}, 'puertos': {'inicio': 1, 'final': '12'}, 'cookie': '', 'profundidad': '12', 'redireccionamiento': True, 'lista_negra': ['']}

try:
    fecha_programada = time.mktime(time.strptime(peticion["fecha"], "%Y-%m-%d"));
except:
    print ("Fecha inválida")
    fecha_programada = 0

peticion["fecha"] = ""

while True:
    fecha_actual = time.time()
    if fecha_actual >= fecha_programada:
        ejecutar(peticion, headers)
        break
    time.sleep(60)
        