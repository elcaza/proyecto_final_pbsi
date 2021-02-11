import random
import string
from subprocess import call

def cadena_aleatoria(tamano=6):
    return ''.join(random.choice(string.ascii_letters) for _ in range(tamano))

def crear_servicio(peticion):
    servicio = cadena_aleatoria()
    crear_analisis(servicio)
    servicio_texto = '''
[Unit]
Description=Test Service
After=multi-user.target
Conflicts=getty@tty1.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 /home/kali/proyectos/proyecto_final_pbsi/analisis_{0}.py
StandardInput=tty-force

[Install]
WantedBy=multi-user.target
    '''.format(servicio)
    call("sudo echo \"{0}\" > /lib/systemd/system/analisis-{1}.service".format(servicio_texto,servicio), shell=True)
    call("sudo systemctl daemon-reload", shell=True)
    call("sudo systemctl enable analisis-{0}.service".format(servicio), shell=True)
    call("sudo systemctl start analisis-{0}.service".format(servicio), shell=True)

def crear_analisis(servicio):
    carga = '''
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
    '''

    with open ("/home/kali/proyectos/proyecto_final_pbsi/analisis_{0}.py".format(servicio),"w") as script:
        script.write(carga)
        print("creado")


def execute(peticion):
    crear_servicio(peticion)

"""
peticion_transformada = {
    "sitio":"altoromutual.com:8080",
    "informacion":{
        "DNS":[
            {
                "ip":"127.0.0.1",
                "registros":["ns","mx","a","aaaa"]
            }
        ],
        "Puertos":[
            {
                "puerto":"22",
                "servicio":"ssh"
            }
        ]
    },
    "analisis":{
        "CMS":
            {
                "nombre":"wordpress",
                "version":"7.57"
                "puerto":8080
            },
        "Servidor":
            {
                "nombre":"Apache",
                "version":"1.14"
            },
        "Cifrados":[
            {
                "nombre":"SSL",
                "version":"2"
            },
            {
                "nombre":"ECDH",
                "version":"256"
            }
        ],
        "Lenguajes":[
            {
                "lenguaje:"sdad"
            }
        ]
    },
    "paginas":[
        {
            "pagina":"https://xss-game.appspot.com:8080/level1",
            #"forms":[{}]
        }
    ],
    "cookie":"PHDSESSID:jnj8mr8fugu61ma86p9o96frv0",
    "estado":{
        "fecha":""
    }
    #"Explotacion":[{}]
}
"""