import subprocess

def modificar_exploit_ip(ip, exploit, exploit_temporal):
    subprocess.check_output("sed \"s/APP_IP/{0}/\" {1} > {2}".format(ip, exploit, exploit_temporal),shell=True)

def otorgar_permisos_exploit(exploit_temp):
    subprocess.check_output("chmod +x {0}".format(exploit_temp),shell=True)

def ejecutar_exploit(exploit):
    resultado = subprocess.check_output(exploit,shell=True)
    return resultado

def eliminiar_exploit_temporal(exploit_temp):
    subprocess.check_output("rm {0}".format(exploit_temp),shell=True)

def execute(ip, exploit, lenguaje):
    exploit_separado = exploit.rsplit(".")
    exploit_temporal = exploit_separado[0] + "_temp." + exploit_separado[1]
    exploit_preparado = lenguaje+exploit_temporal
    modificar_exploit_ip(ip, exploit, exploit_temporal)
    otorgar_permisos_exploit(exploit_temporal)
    resultado = ejecutar_exploit(exploit_preparado)
    eliminiar_exploit_temporal(exploit_temporal)
    print(resultado)