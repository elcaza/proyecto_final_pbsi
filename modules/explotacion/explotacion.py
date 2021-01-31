from subprocess import check_output, CalledProcessError, TimeoutExpired
from os import path
import threading

class Lanzar_exploit(threading.Thread):
    def __init__(self, threadID, nombre, parametros, exploit):
        threading.Thread.__init__(self)
        self.nombre = nombre
        self.threadID = threadID
        self.parametros = parametros
        self.exploit = exploit
        self.resultado = b"Inconcluso"
        
    def run(self):
        print ("Starting " + self.nombre)
        exploit_temporal, exploit_preparado = limpiar_exploit(self.exploit["exploit"], self.exploit["lenguaje"])
        cargar_parametros(self.parametros, self.exploit["exploit"], exploit_temporal)
        otorgar_permisos_exploit(exploit_temporal)
        self.resultado = ejecutar_exploit(exploit_preparado)
        self.resultado = validar_resulado(self.resultado)
        eliminiar_exploit_temporal(exploit_temporal)
        print ("Exiting " + self.nombre)

    def get_resultado(self):
        return self.resultado

# Area para modificar constantes
def modificar_exploit_dominio(dominio, exploit, exploit_temporal):
    try:
        if not path.exists(exploit_temporal):
            check_output("sed \"s|APP_DOMINIO|{0}|g\" {1} > {2}".format(dominio, exploit, exploit_temporal),shell=True)
        else:
            check_output("sed -i \"s|APP_DOMINIO|{0}|g\" {1}".format(dominio, exploit_temporal),shell=True)
    except CalledProcessError:
        print("Ocurrió un error al cambiar el dominio {0} en {1}".format(dominio,exploit))
        
def modificar_exploit_puerto(puerto, exploit, exploit_temporal):
    try:
        if not path.exists(exploit_temporal):
            check_output("sed \"s|APP_PUERTO|{0}|g\" {1} > {2}".format(puerto, exploit, exploit_temporal),shell=True)
        else:
            check_output("sed -i \"s|APP_PUERTO|{0}|g\" {1}".format(puerto, exploit_temporal),shell=True)
    except CalledProcessError:
        print("Ocurrió un error al cambiar el puerto {0} en {1}".format(puerto,exploit))

def modificar_exploit_pagina(pagina, exploit, exploit_temporal):
    try:
        if not path.exists(exploit_temporal):
            check_output("sed \"s|APP_PAGINA|{0}|g\" {1} > {2}".format(pagina, exploit, exploit_temporal),shell=True)
        else:
            check_output("sed -i \"s|APP_PAGINA|{0}|g\" {1}".format(pagina, exploit_temporal),shell=True)
    except CalledProcessError:
        print("Ocurrió un error al cambiar la página {0} en {1}".format(pagina,exploit))  

# Fin del area
def otorgar_permisos_exploit(exploit_temp):
    check_output("chmod +x {0}".format(exploit_temp),shell=True)

def ejecutar_exploit(exploit):
    try:
        resultado = check_output(exploit,shell=True,timeout=300)
    except TimeoutExpired:
        return b"Inconcluso"
    return resultado

def eliminiar_exploit_temporal(exploit_temp):
    check_output("rm {0}".format(exploit_temp),shell=True)

def limpiar_exploit(exploit, lenguaje):
    exploit_separado = exploit.rsplit(".")
    exploit_temporal = exploit_separado[0] + "_temp." + exploit_separado[1]
    exploit_preparado = lenguaje+exploit_temporal
    return exploit_temporal, exploit_preparado

def cargar_parametros(parametros, exploit, exploit_temporal):
    if "dominio" in parametros:
        modificar_exploit_dominio(parametros["dominio"],exploit, exploit_temporal)
    if "puerto" in parametros:
        modificar_exploit_puerto(parametros["puerto"],exploit, exploit_temporal)
    if "pagina" in parametros:
        modificar_exploit_pagina(parametros["pagina"], exploit, exploit_temporal)

def validar_resulado(resultado):
    if b"Exito" in resultado:
        return 1
    elif b"Fracaso" in resultado:
        return -1
    return 0

def obtener_exploits(exploits):
    lista_exploits = []
    for exploit in exploits:
        lista_exploits.append({"exploit":exploit["ruta"],"lenguaje":exploit["lenguaje"]})
    return lista_exploits

def definir_cantidad_hilos(lista_exploits):
    divisor = int(len(lista_exploits) / 4)
    modulo = len(lista_exploits) % 4
    if divisor > 0:
        return 4
    return modulo

def crear_hilos_exploit(parametros, lista_exploits):
    resultados = []
    hijos = []
    hilos = definir_cantidad_hilos(lista_exploits)

    for exploit in range(0, len(lista_exploits), hilos):
        for hilo in range(hilos):
            try:
                hijos.append(Lanzar_exploit(hilo,"Thread-{0}".format(hilo),parametros,lista_exploits[exploit+hilo]))
            except IndexError:
                break

        for hilo in range(hilos):
            hijos[hilo].start()

        for hilo in range(hilos):
            hijos[hilo].join(310)

        for hijo in hijos:
            resultados.append(hijo.get_resultado())
        
        hijos = []

    for res in resultados:
        print("resultado",res)

def execute(parametros, exploits):
    lista_exploits = obtener_exploits(exploits)
    crear_hilos_exploit(parametros, lista_exploits)