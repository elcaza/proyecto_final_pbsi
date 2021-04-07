import random
import string
from subprocess import call
from os import path
import time

class Ejecucion():
    '''
        Clase que permite crear un demonio que siempre se lanza cuando llega el dia (no hora) 
        
        si reinicia el sistema se vuelve a activar el demonio 

        .........
        Atributos
        ---------

        peticion : dict
            peticion que fue enviada al servidor

        archivo : str
            nombre del archivo aleatorio

        servicio : str
            cadena que contiene el nombre del demonio

        archivo_python : str
            cadena que contiene el nombre del archivo python

        ruta : str
            ruta de los archivos a crear

        Metodos
        -------
        cadena_aleatoria(tamano=10):
            regresa una cadena aleatoria de N caracteres

        crear_servicio():
            crear el archivo de configuracion del demonio y lo inicia

        crear_analisis():
            crear el archivo python que estara a la espera de lanzar la peticion sin fecha

        execute():
            crea el demonio
    '''
    def __init__(self, peticion):
        self.peticion = peticion
        self.archivo = self.cadena_aleatoria()
        self.servicio = "analisis_" + self.archivo + ".service"
        self.archivo_python = "analisis_" + self.archivo + ".py"
        self.ruta = path.abspath(path.dirname(__file__)) + "/demonios/"

    def cadena_aleatoria(self, tamano=10):
        '''
            regresa una cadena aleatoria de N caracteres

            Parametros
            ----------
            tamano : int
        '''
        return ''.join(random.choice(string.ascii_letters) for _ in range(tamano))

    def crear_servicio(self):
        '''
            crear el archivo de configuracion del demonio y lo inicia

            necesita privilegios administrativos para la ejecucion, esto actualiza los demonios, lo habilita e inicia
        '''
        self.crear_analisis()
        servicio_texto = '''
[Unit]
Description=Masivo Servicio
After=multi-user.target
Conflicts=getty@tty1.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 {0}{1}
StandardInput=tty-force

[Install]
WantedBy=multi-user.target
        '''.format(self.ruta, self.archivo_python)

        call("sudo echo \"{0}\" > /lib/systemd/system/{1}".format(servicio_texto,self.servicio), shell=True)
        call("sudo systemctl daemon-reload", shell=True)
        call("sudo systemctl enable {0}".format(self.servicio), shell=True)
        call("sudo systemctl start {0}".format(self.servicio), shell=True)

    def crear_analisis(self):
        '''
            crear el archivo python que estara a la espera de lanzar la peticion sin fecha
        '''
        headers = "{\"Content-Type\": \"application/json; charset=utf-8\"}"
        carga = '''
import time
import requests
import json

def ejecutar(peticion, headers):
    r = requests.post("http://127.0.0.1:3000/ejecucion",data=json.dumps(peticion), headers=headers)
    print(r.text)

headers = {0}

peticion = {1}

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
        '''.format(headers, str(self.peticion))
        with open (self.ruta + self.archivo_python,"w") as script:
            script.write(carga)
            print("Creado {0}".format(self.archivo_python))

    def execute(self):
        '''
            crea el demonio
        '''
        self.crear_servicio()

def execute(peticion):
    '''
        lanza la ejecucion/creacion del demonio
    '''
    ejecucion = Ejecucion(peticion)
    ejecucion.execute()