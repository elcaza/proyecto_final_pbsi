# Importaciones
## Flask
from weakref import ProxyTypes
from modules.strings import COLECCION_ANALISIS
import re
from flask import Flask, render_template, request
from flask_cors import CORS

## Utileria
from base64 import decode, encode
from os import path
from datetime import datetime
import plotly.graph_objects as go
import json
from time import sleep

## Modulos
from modules.obtencion_informacion import obtener_informacion
from modules.alertas import alertas
from modules.analisis import analisis
from modules.exploits import exploits as exp
from modules.explotacion import explotacion
from modules.fuzzing import fuzzing
from modules.modelo.conector import Conector
from modules.reportes import reportes
from modules.ejecucion import ejecucion as programacion

root = path.abspath(path.dirname(__file__))
app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = 'ojalaSePudieraLlorar_grasa'

'''
    Modo de ejecucion:
        
        Ejecucion -> Obtener_informacion -> Análisis [Ejecucion de Fuzzing[Hilos] -> Lista de vulnerabilidades y Lista de posibles vulnerabilidades]
            -> Identificacion -> Explotacion [-> Lista de vulnerabilidades, Lista de posibles vulnerabilidades y Lista de Fracasos]
                -> Reporte

        Base de exploits
        Consulta
'''

def iniciar_analisis(peticion):
    con = Conector()

    if peticion["ejecucion"] != "":
        programacion.execute(peticion)
        return "Análisis programado"
    else:
        peticion_proceso = {
            "sitio":peticion["sitio"],
            "cookie":peticion["cookie"],
            "fecha":datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
            "profundidad":peticion["profundidad"]
        }

        peticion_reporte = {
            "sitio":peticion_proceso["sitio"],
            "fecha":peticion_proceso["fecha"],
            "analisis":[],
        }

        peticion_alerta = {
            "subject":"Alerta generada automáticamente",
            "sitios":[],
            "fecha":datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
        }

        numero_grafica = 0

        print("Iniciando Información")
        # respuesta_obtener_informacion = obtener_informacion.execute(peticion)
        # peticion_proceso["informacion"] = respuesta_obtener_informacion
        # numero_grafica = reporte_informacion(peticion_proceso, peticion_reporte, numero_grafica)

        print("Iniciando Análisis")
        execute_analisis(peticion_proceso, peticion_reporte)
        ############################################################# FUZZING #############################################################

        print("Iniciando Fuzzing")
        #peticion_proceso["analisis"]["paginas"] = [{"pagina":"http://localhost/drupal7/INSTALL.pgsql.txt","forms":{}}]
        numero_grafica = execute_fuzzing(peticion_proceso, peticion_alerta, peticion_reporte, numero_grafica)

        print("Iniciando Explotacion")
        numero_grafica = execute_explotacion(con, peticion_proceso, peticion_alerta, peticion_reporte, numero_grafica)

        print("Iniciando Reporte")
        execute_reporte(peticion_reporte)

        print("Enviando alertas")
        execute_alerta(peticion_alerta)
        
        print("Guardando analisis")
        con.guardar_analisis(peticion_proceso)

        return "Reporte generado"

def guardar_exploit(peticion):
    con = Conector()
    exploit = exp.execute(peticion)
    con.exploit_insertar_datos(exploit)
    return "True"

def consulta_buscar_general():
    con = Conector()
    consulta = {}
    ultimo_analisis = con.obtener_analisis_totales()
    ultima_fecha = con.obtener_ultima_fecha()
    analisis = con.obtener_analisis_generales()

    consulta["ultimo_analisis"] = ultimo_analisis
    consulta["ultima_fecha"] = ultima_fecha
    consulta["analisis"] = analisis
    respueta_json = json.dumps(consulta)
    return respueta_json

def consulta_buscar_analisis(peticion):
    con = Conector()
    analisis = con.obtener_analisis(peticion)
    if analisis == None:
        return "No hay coincidencias"
    respueta_json = json.dumps(analisis)
    return respueta_json

def consulta_reporte(peticion):
    con = Conector()
    analisis = con.obtener_analisis(peticion)
    numero_grafica = 0
    peticion_reporte = {
        "sitio":analisis["sitio"],
        "fecha":analisis["fecha"],
        "analisis":[],
    }
    numero_grafica = reporte_informacion(analisis, peticion_reporte, numero_grafica)
    numero_grafica = reportes_fuzzing(analisis, peticion_reporte, numero_grafica)
    numero_grafica = reporte_explotacion(analisis, peticion_reporte, numero_grafica)
    return "Consulta de reporte creado"
"""
    Modulos
"""

def execute_analisis(peticion_proceso, peticion_reporte):
    respuesta_analisis = analisis.execute(peticion_proceso["sitio"])
    peticion_proceso["analisis"] = respuesta_analisis
    reporte_analisis(peticion_proceso, peticion_reporte)

# Puede que truene en fuzzing_enviar_pagina
def execute_fuzzing(peticion_proceso, peticion_alerta, peticion_reporte, numero_grafica):
    fuzzing_enviar_pagina(peticion_proceso)
    alertas_fuzzing(peticion_proceso, peticion_alerta)
    numero_grafica = reportes_fuzzing(peticion_proceso, peticion_reporte, numero_grafica)
    return numero_grafica

# Puede que truene en explotacion_enviar_exploit
def execute_explotacion(con, peticion_proceso, peticion_alerta, peticion_reporte, numero_grafica):
    datos_explotacion, datos_identificados = obtener_datos_consulta_exploits(peticion_proceso)
    explotacion_enviar_exploit(con, datos_identificados, datos_explotacion, peticion_proceso)
    alertas_explotacion(peticion_proceso, peticion_alerta)
    numero_grafica = reporte_explotacion(peticion_proceso, peticion_reporte, numero_grafica)
    return numero_grafica

# No truena
def execute_alerta(peticion_alerta):
    resultado = enviar_alertas(peticion_alerta)
    return resultado

# No truena
def execute_reporte(peticion_reporte):
    reportes.execute(peticion_reporte)
    
def fuzzing_enviar_pagina(peticion_proceso):
    for posicion_pagina in range(len(peticion_proceso["analisis"]["paginas"])):
        json_fuzzing = {
            "url":peticion_proceso["analisis"]["paginas"][posicion_pagina]["pagina"],
            "hilos":4,
            "cookie":peticion_proceso["cookie"]
        }
        forms = fuzzing.execute(json_fuzzing)
        if forms != False:
            peticion_proceso["analisis"]["paginas"][posicion_pagina].update(forms)

# No truena
def explotacion_enviar_exploit(con, datos_identificados, datos_explotacion, peticion_proceso):
    exploits = buscar_exploits(datos_identificados, con)
    if len(exploits) != 0:
        exploits = list({(e["ruta"],e["lenguaje"]):e for e in exploits}.values())
        explotaciones = explotacion.execute(datos_explotacion,exploits)
        peticion_proceso.update(explotaciones)
    else:
        peticion_proceso.update({"explotaciones":{}})
"""
    Alertas
"""
# No truena
def enviar_alertas(peticion_alerta):
    alertas.execute(peticion_alerta)

# No truena
def alertas_fuzzing(peticion_proceso, peticion_alerta):
    for posicion_pagina in range(len(peticion_proceso["analisis"]["paginas"])):
        fuzzing_alertas = fuzzing_obtener_alertas(peticion_proceso["analisis"]["paginas"][posicion_pagina])
        peticion_alerta["sitios"].append(fuzzing_alertas)        

# No truena
def alertas_explotacion(peticion_proceso, peticion_alerta):
    explotacion_alertas = explotacion_obtener_alertas(peticion_proceso)
    peticion_alerta["sitios"].append(explotacion_alertas)
"""
    Reportes
"""
def reporte_informacion(peticion_proceso, peticion_reporte, numero_grafica):
    datos_host = {}
    datos_host["host"] = peticion_proceso["informacion"]["Dnsdumpster"]["host"][0]["dominio"]
    if datos_host["host"] == "":
        datos_host["host"] = peticion_proceso["sitio"]
    datos_host["ip"] = peticion_proceso["informacion"]["Dnsdumpster"]["host"][0]["ip"]
    datos_host["dns_inverso"] = peticion_proceso["informacion"]["Dnsdumpster"]["host"][0]["dns_inverso"]
    datos_host["pais"] = peticion_proceso["informacion"]["Dnsdumpster"]["host"][0]["pais"]
    datos_host["cabecera"] = peticion_proceso["informacion"]["Dnsdumpster"]["host"][0]["cabecera"]
    informacion_estadisticas = informacion_obtener_estadisticas(peticion_proceso)

    numero_grafica = reportes_informacion_crear(informacion_estadisticas, peticion_reporte, datos_host, numero_grafica)
    return numero_grafica

def reporte_analisis(peticion_proceso, peticion_reporte):
    analisis = {}
    analisis["servidor"] = analisis_obtener_servidor(peticion_proceso["analisis"]["servidor"], "Servidor") # Nombre y versión
    analisis["cms"] = analisis_obtener_servidor(peticion_proceso["analisis"]["cms"], "CMS") # Nombre y versión
    analisis["librerias"] = analisis_obtener_cms_datos(peticion_proceso["analisis"]["librerias"],"Libreria") #  Nombre y versión
    analisis["frameworks"] = analisis_obtener_cms_datos(peticion_proceso["analisis"]["frameworks"],"Framework") # Nombre y versión
    analisis["lenguajes"] = analisis_obtener_cms_datos(peticion_proceso["analisis"]["lenguajes"],"Lenguaje") # Nombre y versión

    analisis["plugins"] = analisis_obtener_datos(peticion_proceso["analisis"]["plugins"],"Plugins") # Listado
    analisis["archivos"] = analisis_obtener_datos(peticion_proceso["analisis"]["archivos"], "Archivos") # Listado
    analisis["vulnerabilidades"] = analisis_obtener_datos(peticion_proceso["analisis"]["vulnerabilidades"], "Vulnerabilidades conocidas") # Listado
    analisis["headers"] = analisis_obtener_datos(peticion_proceso["analisis"]["headers"],"Headers") # Listado

    analisis["paginas"] = analisis_obtener_paginas(peticion_proceso["analisis"]["paginas"]) # Total

    reportes_analisis_crear(analisis, peticion_reporte)

#########
def analisis_obtener_servidor(datos, tipo):
    nombre = "No se encontró {0}".format(tipo)
    version = "NA"
    if "nombre" in datos:
        if datos["nombre"] != "":
            nombre = datos["nombre"]
    if "version" in datos:
        if datos["version"] != "":
            version = datos["version"]
    return [[tipo, nombre.capitalize(), version]]

def analisis_obtener_cms_datos(datos, tipo):
    resultados = []
    for dato in datos:
        nombre = "No se encontró {0}".format(tipo)
        version = "NA"
        if "nombre" in dato:
            if dato["nombre"] != "":
                nombre = dato["nombre"]
                if "version" in dato:
                    if dato["version"] != "":
                        for numero_version in dato["version"]:
                            if numero_version != "":
                                version += numero_version + ", "
        resultados.append([tipo, nombre.capitalize(), version])
    return resultados

def analisis_obtener_datos(datos, tipo): 
    if len(datos) != 0:
        return [[dato] for dato in datos]
    return [["No se encontraron {0}".format(tipo)]]

def analisis_obtener_paginas(datos): return [[len(datos)]]

########

# Puede que truene en peticion_proceso[analisis][paginas]
def reportes_fuzzing(peticion_proceso, peticion_reporte, numero_grafica):
    fuzzing_estadistica_general = []
    fuzzing_estadistica_individual = []
    paginas = len(peticion_proceso["analisis"]["paginas"])
    for posicion_pagina in range(paginas):
        fuzzing_estadistica_individual.append(estaditisticas_fuzzing(peticion_proceso["analisis"]["paginas"][posicion_pagina]))
    
    for individual in fuzzing_estadistica_individual:
        xss =+ individual[1]
        sqli =+ individual[2]
        lfi =+ individual[3]

    fuzzing_estadistica_general.append(peticion_proceso["sitio"])
    fuzzing_estadistica_general.append(xss)
    fuzzing_estadistica_general.append(sqli)
    fuzzing_estadistica_general.append(lfi)
    numero_grafica = reportes_fuzzing_crear(fuzzing_estadistica_general, fuzzing_estadistica_individual, peticion_reporte, numero_grafica)
        
    return numero_grafica

# No truena
def reporte_explotacion(peticion_proceso, peticion_reporte, numero_grafica):
    explotacion_estadisticas = estadisticas_explotacion(peticion_proceso)
    numero_grafica = reportes_explotacion_crear(explotacion_estadisticas, peticion_reporte, numero_grafica)
    return numero_grafica

"""
    Generar reportes
"""
# Informacion
def informacion_datos_individuales_dns(informacion_estadisticas, reporte):
    registros_etiqueta = ["MX","TXT","DNS"]
    mx = informacion_estadisticas["mx"]
    txt = informacion_estadisticas["txt"]
    dns = informacion_estadisticas["dns"]
    registros = [mx,txt,dns]
    informacio_diagrama = go.Figure(data=[go.Pie(labels=registros_etiqueta, values=registros)])
    informacio_diagrama.write_html(reporte, full_html=False, include_plotlyjs="cdn")
    return registros, registros_etiqueta

def informacion_datos_individuales_puertos(informacion_estadisticas, reporte):
    puertos_estado = ["Abiertos","Filtrados"]
    filtrados = informacion_estadisticas["filtrados"]
    abiertos = informacion_estadisticas["abiertos"]
    puertos = [abiertos,filtrados]
    informacio_diagrama = go.Figure(data=[go.Pie(labels=puertos_estado, values=puertos)])
    informacio_diagrama.write_html(reporte, full_html=False, include_plotlyjs="cdn")
    return puertos, puertos_estado

# Fuzzing
def reportes_fuzzing_crear_general_grafica(fuzzing_estadisticas,reporte):
    xss = fuzzing_estadisticas[0][1]
    sqli = fuzzing_estadisticas[0][2]
    lfi = fuzzing_estadisticas[0][3]
    ataques = ["XSS","SQLi","LFI"]

    fuzzing_diagrama = go.Figure(data=[go.Pie(labels=ataques, values=[xss,sqli,lfi])])
    fuzzing_diagrama.write_html(reporte, full_html=False, include_plotlyjs="cdn")

# Explotacion

# No truena
def reportes_explotacion_crear_general_grafica(explotacion_estadisticas,reporte):
    exito = 0
    fracaso = 0
    inconcluso = 0
    ataques = ["Exito","Fracaso","Inconcluso"]
    if explotacion_estadisticas != 0:
        for explotacion in explotacion_estadisticas:
            if explotacion[1] == "Exitoso":
                exito += 1
            if explotacion[1] == "Fracaso":
                fracaso += 1
            if explotacion[1] == "Inconcluso":
                inconcluso += 1
    ataques_resultado = [exito, fracaso, inconcluso]
    fuzzing_diagrama = go.Figure(data=[go.Pie(labels=ataques, values=ataques_resultado)])
    
    fuzzing_diagrama.write_html(reporte, full_html=False, include_plotlyjs="cdn")

"""
    Crear reportes
"""
# Informacion
def reportes_informacion_crear_individual_dns(registros, registros_etiqueta, reporte, sitio):
    analisis = {
                "categoria":"Informacion",
                "titulo":"DNS",
                "grafica":reporte,
                "cabecera":["Sitio","Motivo"],
                "datos":[
                    [sitio,"Registros MX: {0}".format(registros[0])],
                    [sitio,"Registros TXT: {0}".format(registros[1])],
                    [sitio,"Registros DNS: {0}".format(registros[2])]],
    }
    return analisis

def reportes_informacion_crear_individual_puertos(puertos, puertos_estado, reporte, sitio):
    analisis = {
                "categoria":"Informacion",
                "titulo":"Puertos",
                "grafica":reporte,
                "cabecera":["Sitio","Motivo","Estado"],
                "datos":[
                    [sitio,"Puertos abiertos: {0}".format(puertos[0]),puertos_estado[0]],
                    [sitio,"Puertos filtrados: {0}".format(puertos[1]),puertos_estado[1]]],
    }
    return analisis

def reportes_informacion_crear_general(datos_host):
    analisis = {
                "categoria":"Informacion",
                "titulo":"Resultados generales",
                "grafica":"",
                "cabecera":["Nombre","Descripción"],
                "datos":[
                    ["Host",datos_host["host"]],
                    ["IP",datos_host["ip"]],
                    ["DNS Inverso",datos_host["dns_inverso"]],
                    ["País",datos_host["pais"]],
                    ["Servidor",datos_host["cabecera"]]],
    }
    return analisis

def reportes_informacion_crear(informacion_estadisticas, peticion_reporte, datos_host, numero_grafica):
    reporte = root+"/modules/reportes/ifram_grafica_info"
    
    analisis = reportes_informacion_crear_general(datos_host)
    peticion_reporte["analisis"].append(analisis)

    puertos, puertos_estado = informacion_datos_individuales_puertos(informacion_estadisticas,reporte+"{0}.html".format(numero_grafica))
    analisis = reportes_informacion_crear_individual_puertos(puertos, puertos_estado,reporte+"{0}.html".format(numero_grafica),peticion_reporte["sitio"])
    peticion_reporte["analisis"].append(analisis)
    numero_grafica += 1
    
    puertos, puertos_estado = informacion_datos_individuales_dns(informacion_estadisticas,reporte+"{0}.html".format(numero_grafica))
    analisis = reportes_informacion_crear_individual_dns(puertos, puertos_estado,reporte+"{0}.html".format(numero_grafica),peticion_reporte["sitio"])
    peticion_reporte["analisis"].append(analisis)
    numero_grafica += 1
    return numero_grafica

# Analisis
def reportes_analisis_crear_general(datos_analisis):
    analisis = []
    datos = {}
    datos["servidor"] = datos_analisis["servidor"] + datos_analisis["cms"]
    datos["cms"] = datos_analisis["librerias"] + datos_analisis["frameworks"] + datos_analisis["lenguajes"]
    datos["plugins"] = datos_analisis["plugins"]
    datos["archivos"] = datos_analisis["archivos"] 
    datos["vulnerabilidades"] = datos_analisis["vulnerabilidades"]
    datos["headers"] = datos_analisis["headers"]
    titulo_bandera = 0

    for dato in datos:
        if dato == "servidor":
            analisis_individual = {
                        "categoria":"Analisis",
                        "titulo":"Datos generales",
                        "grafica":"",
                        "cabecera":["Tipo","Nombre","Versión"],
                        "datos":datos[dato]
            }
        elif dato == "cms":
            analisis_individual = {
                        "categoria":"",
                        "titulo":"Librerías, Frameworks, Lenguajes",
                        "grafica":"",
                        "cabecera":["Tipo","Nombre","Versión"],
                        "datos":datos[dato]
            }
        else:
            if titulo_bandera == 0:
                titulo_nombre = "Interés"
                titulo_bandera = 1
            else: 
                titulo_nombre = ""
            analisis_individual = {
                        "categoria":"",
                        "titulo":titulo_nombre,
                        "grafica":"",
                        "cabecera":[dato.capitalize()],
                        "datos":datos[dato]
            }
        analisis.append(analisis_individual)


    return analisis

def reportes_analisis_crear(datos_analisis, peticion_reporte):
    analisis = reportes_analisis_crear_general(datos_analisis)
    for valor in analisis:
        peticion_reporte["analisis"].append(valor)

# Fuzzing
def reportes_fuzzing_crear_general(fuzzing_estadistica_general, reporte):
    analisis = {
                "categoria":"Fuzzing",
                "titulo":"Resultados generales",
                "grafica":reporte,
                "cabecera":["Sitio","XSS","SQLi","LFI"],
                "datos":[fuzzing_estadistica_general]
    }
    return analisis

def reportes_fuzzing_crear_individual(fuzzing_estadistica_individual):
    analisis = {
                "categoria":"",
                "titulo":"Resultados individuales",
                "grafica":"",
                "cabecera":["Página","XSS","SQLi","LFI"],
                "datos":fuzzing_estadistica_individual
    }
    return analisis

def reportes_fuzzing_crear(fuzzing_estadistica_general, fuzzing_estadistica_individual, peticion_reporte, numero_grafica):
    reporte = root + "/modules/reportes/ifram_grafica"
    reporte_grafica = reporte + "{0}.html".format(numero_grafica)
    numero_grafica += 1

    reportes_fuzzing_crear_general_grafica(fuzzing_estadistica_general, reporte_grafica )
    analisis = reportes_fuzzing_crear_general(fuzzing_estadistica_general, reporte_grafica )
    peticion_reporte["analisis"].append(analisis)
    
    analisis = reportes_fuzzing_crear_individual(fuzzing_estadistica_individual)
    peticion_reporte["analisis"].append(analisis)

    return numero_grafica

# Explotacion

# No truena
def reportes_explotacion_crear_general(explotacion_estadisticas, reporte):
    analisis = {
                "categoria":"Explotacion",
                "titulo":"Resultados generales",
                "grafica":reporte,
                "cabecera":["Exploit","Resultado"],
                "datos":explotacion_estadisticas
    }
    return analisis

# No truena
def reportes_explotacion_crear(explotacion_estadisticas, peticion_reporte, numero_grafica):
    reporte = root + "/modules/reportes/ifram_grafica_explotacion"
    reporte_grafica = reporte + "{0}.html".format(numero_grafica)
    numero_grafica += 1

    reportes_explotacion_crear_general_grafica(explotacion_estadisticas,reporte_grafica)
    analisis = reportes_explotacion_crear_general(explotacion_estadisticas, reporte_grafica)
    peticion_reporte["analisis"].append(analisis)
    
    return numero_grafica

"""
    Utilidades
        Falta obtener los datos para consultar los exploits, estos se recuperan del analisis y obtener informacion
"""

# Puede que truene
def obtener_datos_consulta_exploits(peticion_proceso):
    datos_identificados = {"software":[],"cms":[], "cve":[], "profundidad": 2}
    
    datos_identificados["software"].extend(obtener_software_version_unica(peticion_proceso["analisis"], "servidor"))
    cms = obtener_software_version_unica(peticion_proceso["analisis"], "cms")

    if len(cms) != 0:
        cms_nombre = cms[0]["software_nombre"]
    else:
        cms_nombre = ""

    datos_identificados["software"].extend(cms)
    datos_identificados["software"].extend(obtener_sofware_versiones(peticion_proceso["analisis"], "lenguajes"))
    datos_identificados["software"].extend(obtener_sofware_versiones(peticion_proceso["analisis"], "frameworks"))
    datos_identificados["software"].extend(obtener_sofware_versiones(peticion_proceso["analisis"], "librerias"))
    datos_identificados["cms"].extend(obtener_cms_version_unica(peticion_proceso["analisis"], "dato", cms_nombre))
    
    if "vulnerabilidades" in peticion_proceso["analisis"]:
        for cve in peticion_proceso["analisis"]["vulnerabilidades"]:
            datos_identificados["cve"].append(cve)

    datos_identificados["profundidad"] = peticion_proceso["profundidad"]

    if peticion_proceso["sitio"].startswith("https"):
        datos_explotacion = {"sitio":peticion_proceso["sitio"],"puertos":["443"]}
    else:
        datos_explotacion = {"sitio":peticion_proceso["sitio"],"puertos":["80"]}

    if "informacion" in peticion_proceso:
        for puerto in peticion_proceso["informacion"]["Puertos"]["abiertos"]:
            if puerto != "80" or puerto != "443":
                datos_explotacion["puertos"].append(puerto["puerto"])

    return datos_explotacion, datos_identificados

def obtener_sofware_versiones(peticion_proceso, caracteristica):
    datos_identificados = []
    nombre = ""
    version = ""
    if caracteristica in peticion_proceso:
        if "nombre" in peticion_proceso[caracteristica]:
            nombre= peticion_proceso[caracteristica]["nombre"]
        if "version" in peticion_proceso[caracteristica]:
            if len(peticion_proceso[caracteristica]["version"]) > 0:
                for tipo in peticion_proceso[caracteristica]["version"]:
                    version = peticion_proceso[caracteristica]["version"][tipo]
                    datos_identificados.append({"software_nombre":nombre,"software_version":version})
            if len(peticion_proceso[caracteristica]["version"]) == 0:
                datos_identificados.append({"software_nombre":nombre,"software_version":""}) 
    return datos_identificados

def obtener_software_version_unica(peticion_proceso, caracteristica):
    datos_identificados = []
    nombre = ""
    version = ""
    if caracteristica in peticion_proceso:
        if "nombre" in peticion_proceso[caracteristica]:
            nombre = peticion_proceso[caracteristica]["nombre"]
        if "version" in peticion_proceso[caracteristica]:
            version = peticion_proceso[caracteristica]["version"]
            version = version.replace("x","")
        datos_identificados.append({"software_nombre":nombre,"software_version":version})
    return datos_identificados

def obtener_cms_version_unica(peticion_proceso, caracteristica, cms):
    datos_identificados = []
    nombre = ""
    version = ""
    if caracteristica in peticion_proceso:
        if "nombre" in peticion_proceso[caracteristica]:
            nombre = peticion_proceso[caracteristica]["nombre"]
        if "version" in peticion_proceso[caracteristica]:
            version = peticion_proceso[caracteristica]["version"]
        datos_identificados.append({"cms_nombre":cms,"cms_categoria":caracteristica, "cms_extension_nombre":nombre,"cms_extension_version":version})
    return datos_identificados

# No truena
def buscar_exploits(datos_identificados, con):
    exploits = []
    for software in datos_identificados["software"]:
        json_software = {
            "software_nombre":software["software_nombre"].strip(),
            "software_version":software["software_version"].strip(),
        }
        exploit_software = con.exploit_buscar_software(json_software,datos_identificados["profundidad"])
        for exploit in exploit_software["exploits"]:
            exploits.append(exploit)
    
    for cms in datos_identificados["cms"]:
        json_cms = {
            "cms_nombre":cms["cms_nombre"].strip(),
            "cms_categoria":cms["cms_categoria"].strip(),
            "cms_extension_nombre":cms["cms_extension_nombre"].strip(),
            "cms_extension_version":cms["cms_extension_version"].strip()
        }
        exploit_cms = con.exploit_buscar_cms(json_cms,datos_identificados["profundidad"])
        for exploit in exploit_cms["exploits"]:
            exploits.append(exploit)

    for cve in datos_identificados["cve"]:
        exploit_cve = con.exploit_buscar_cve(cve.strip())
        for exploit in exploit_cve["exploits"]:
            exploits.append(exploit)
    return exploits

"""
   Módulo de consultas 
"""
# Obtener informacion del sitio
def obtener_informacion_sitio(con, sitio):
    sitio = con.informacion_sitio(sitio)
    return sitio

# Obtener informacion del analisis
def obtener_informacion_analisis(con, sitio):
    analisis = con.analisis_sitio(sitio)
    return analisis

# Obtener informacion del fuzzing
def obtener_informacion_fuzzing(con, sitio):
    fuzzing = con.fuzzing_sitio(sitio)
    return fuzzing

# Obtener informacion de la explotacion
def obtener_informacion_explotacion(con, sitio):
    explotacion = con.explotacion_sitio(sitio)
    return explotacion

"""
    Obtener estadísticas
        
"""
def informacion_obtener_estadisticas(informacion):
    datos = {}
    datos["txt"] = len(informacion["informacion"]["Dnsdumpster"]["txt"])
    datos["dns"] = len(informacion["informacion"]["Dnsdumpster"]["dns"])
    datos["mx"] = len(informacion["informacion"]["Dnsdumpster"]["mx"])

    datos["filtrados"] = len(informacion["informacion"]["Puertos"]["filtrados"])
    datos["abiertos"] = len(informacion["informacion"]["Puertos"]["abiertos"])

    return datos

def estaditisticas_fuzzing(forms):
    forms_estadisticas = ["",0,0,0]
    forms_estadisticas[0] = (forms["pagina"])
    for form in forms["forms"]:
        for resultados in forms["forms"][form]:
            for ataque in ["xss","sqli","lfi"]:
                resultado_ataque = resultados[ataque]
                if resultado_ataque == True:
                    if ataque == "xss":
                        forms_estadisticas[1] += 1
                    elif ataque == "sqli":
                        forms_estadisticas[2] += 1
                    elif ataque == "lfi":
                        forms_estadisticas[3] += 1
                    
    return forms_estadisticas

# No truena
def fuzzing_obtener_alertas(forms):
    forms_alertas = {}
    forms_alertas["pagina"] = forms["pagina"]
    motivo = ""
    for form in forms["forms"]:
        xss = 0
        sqli = 0
        lfi = 0
        for pagina in forms["forms"][form]:
            if pagina["xss"] == True:
                xss += 1
            if pagina["sqli"] == True:
                sqli += 1
            if pagina["lfi"] == True:
                lfi += 1
        motivo += '''
        Form: {0}
        {1} XSS Detectados
        {2} SQLi Detectados
        {3} LFI Detectados
        '''.format(form, xss, sqli, lfi)
    forms_alertas["motivo"] = motivo
    forms_alertas["estado"] = "Posiblemente vulnerable"
    return forms_alertas

def explotacion_obtener_alertas(explotaciones):
    explotacion_alertas = {}
    explotacion_alertas["sitio"] = explotaciones["sitio"]
    motivo = ""
    for exploit in explotaciones["explotaciones"]:
        for puerto in explotaciones["explotaciones"][exploit]:
            if explotaciones["explotaciones"][exploit][puerto] == 1:
                motivo += "Exploit {0} ejecutado con éxito en puerto [{1}]\n".format(exploit,puerto)
    explotacion_alertas["motivo"] = motivo
    explotacion_alertas["estado"] = "Vulnerable"
    return explotacion_alertas

def estadisticas_explotacion(explotaciones):
    explotacion = []
    for exploit in explotaciones["explotaciones"]:
        explotacion_temporal = ["",""]
        explotacion_temporal[0] = exploit
        for puerto in explotaciones["explotaciones"][exploit]:
            if explotaciones["explotaciones"][exploit][puerto] == 1:
                explotacion_temporal[1] = "Exitoso"
                break
            if explotaciones["explotaciones"][exploit][puerto] == 0:
                explotacion_temporal[1] = "Inconcluso"
            if explotaciones["explotaciones"][exploit][puerto] == -1:
                explotacion_temporal[1] = "Fracaso"
        explotacion.append(explotacion_temporal.copy())
    return explotacion

@app.route("/ejecucion", methods=["GET","POST"])
def ejecucion():
    if request.method == "POST":
        peticion_json = request.json
        #validar_json_ejecucion(peticion_json)
        respuesta = iniciar_analisis(peticion_json)
        return respuesta
    if request.method == "GET":
        return "GET no"

@app.route("/consulta-buscar", methods=["GET","POST"])
def consulta_buscar():
    if request.method == "POST":
        respuesta = consulta_buscar_general()
        return respuesta

@app.route("/consulta-analisis", methods=["GET","POST"])
def consulta_analisis():
    if request.method == "POST":
        peticion_json = request.get_json()
        #validar_json_consulta(peticion_json)
        respuesta = consulta_buscar_analisis(peticion_json)
        return respuesta

@app.route("/reporte", methods=["GET","POST"])
def reporte():
    if request.method == "POST":
        peticion_json = request.get_json()
        #validar_json_consulta(peticion_json)
        respuesta = consulta_reporte(peticion_json)
        return respuesta

@app.route("/exploits", methods=["GET","POST"])
def exploits():
    if request.method == "POST":
        peticion_json = request.get_json()
        #validar_json_exploit(peticion_json)    
        respuesta = guardar_exploit(peticion_json)
        return respuesta
    if request.method == "GET":
        return "GET no"

@app.route("/prueba", methods=["GET","POST"])
def prueba():
    if request.method == "POST":
        sleep(15)
        return "respuesta"
    if request.method == "GET":
        return "GET no"


# Ejecucion de Flask
'''
    Nota:
        Es necesario usar WSGI para implementar el WebService, por qué?
            Si truena en algún lado continua con la ejecución y levanta otra "instancia"
            Permite más de una conexión
            Permite personalizar las opciones de seguridad
            Pueden ser:
                Apache (Algo complicado, pero más personalizable)
                Gunicorn (Muy fácil)
                Bjoern (Es muy rápido, no lo he probado) 
'''

if __name__ == "__main__":
    app.run(host='127.0.0.1', port=3000, debug=True)    