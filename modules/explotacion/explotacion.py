from subprocess import check_output
from os import path


# Area para modificar constantes
def modificar_exploit_ip(ip, exploit, exploit_temporal):
    if not path.exists(exploit_temporal):
        check_output("sed \"s/APP_IP/{0}/g\" {1} > {2}".format(ip, exploit, exploit_temporal),shell=True)
    else:
        check_output("sed -i \"s/APP_IP/{0}/g\" {1}".format(ip, exploit_temporal),shell=True)

def modificar_exploit_puerto(puerto, exploit, exploit_temporal):
    if not path.exists(exploit_temporal):
        check_output("sed \"s/APP_PUERTO/{0}/g\" {1} > {2}".format(puerto, exploit, exploit_temporal),shell=True)
    else:
        check_output("sed -i \"s/APP_PUERTO/{0}/g\" {1}".format(puerto, exploit_temporal),shell=True)
# Fin del area
def otorgar_permisos_exploit(exploit_temp):
    check_output("chmod +x {0}".format(exploit_temp),shell=True)

def ejecutar_exploit(exploit):
    resultado = check_output(exploit,shell=True)
    return resultado

def eliminiar_exploit_temporal(exploit_temp):
    check_output("rm {0}".format(exploit_temp),shell=True)

def limpiar_exploit(exploit, lenguaje):
    exploit_separado = exploit.rsplit(".")
    exploit_temporal = exploit_separado[0] + "_temp." + exploit_separado[1]
    exploit_preparado = lenguaje+exploit_temporal
    return exploit_temporal, exploit_preparado

def cargar_parametros(parametros, exploit, exploit_temporal):
    if "ip" in parametros:
        modificar_exploit_ip(parametros["ip"],exploit, exploit_temporal)
    if "puerto" in parametros:
        modificar_exploit_puerto(parametros["puerto"],exploit, exploit_temporal)

def validar_resulado(resultado):
    if b"Exito" in resultado:
        return 1
    elif b"Fracaso" in resultado:
        return -1
    return 0

def execute(parametros, exploit, lenguaje):
    exploit_temporal, exploit_preparado = limpiar_exploit(exploit, lenguaje)
    cargar_parametros(parametros, exploit, exploit_temporal)
    otorgar_permisos_exploit(exploit_temporal)
    resultado = ejecutar_exploit(exploit_preparado)
    eliminiar_exploit_temporal(exploit_temporal)
    #Mongo
    if validar_resulado(resultado) == 1:
        print("Exito")
    elif validar_resulado(resultado) == 0:
        print("Inconcluso")
    else:
        print("Fracaso")