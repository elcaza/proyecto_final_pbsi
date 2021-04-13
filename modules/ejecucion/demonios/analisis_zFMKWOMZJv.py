
import time
import requests
import json

def ejecutar(peticion, headers):
    r = requests.post("http://127.0.0.1:3000/ejecucion",data=json.dumps(peticion), headers=headers)
    print(r.text)

headers = {"Content-Type": "application/json; charset=utf-8"}

peticion = {'sitio': 'https://localhost/DVWA-master/', 'fecha': '2021-04-13', 'archivo': '', 'puertos': {'inicio': 1, 'final': '11111'}, 'cookie': 'PHPSESSID:gbrb98le5052798b2l7vfcjhhb', 'profundidad': '2', 'redireccionamiento': True, 'lista_negra': ['http://localhost/DVWA-master/logout.php', 'https://localhost/DVWA-master/logout.php', 'http://localhost/DVWA-master/./logout.php', 'https://localhost/DVWA-master/./logout.php', 'http://localhost/logout.php', 'https://localhost/logout.php', 'http://localhost/DVWA-master/logout.php', 'https://localhost/DVWA-master/logout.php', 'http://localhost/DVWA-master/setup.php', 'https://localhost/DVWA-master/setup.php']}

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
        