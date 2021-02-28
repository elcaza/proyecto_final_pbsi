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
        respuesta_analisis = analisis.execute(peticion_proceso["sitio"])
        peticion_proceso["analisis"] = respuesta_analisis
        reporte_analisis(peticion_proceso, peticion_reporte)
        ############################################################# FUZZING #############################################################

        print("Iniciando Fuzzing")
        #peticion_proceso["analisis"]["paginas"] = [{"pagina":"http://localhost/drupal7/INSTALL.pgsql.txt","forms":{}},
        #                                {"pagina":"http://localhost/drupal7/cron.php","forms":{}}]
        enviar_fuzzing(peticion_proceso)
        alertas_fuzzing(peticion_proceso, peticion_alerta)
        numero_grafica = reporte_fuzzing(peticion_proceso, peticion_reporte, numero_grafica)

        print("Iniciando Explotacion")
        datos_explotacion, datos_identificados = obtener_datos_consulta_exploits(peticion_proceso)
        enviar_explotacion(con, datos_identificados, datos_explotacion, peticion_proceso)
        alertas_explotacion(peticion_proceso, peticion_alerta)
        numero_grafica = reporte_explotacion(peticion_proceso, peticion_reporte, numero_grafica)
        
        print("Creando el reporte")
        reportes.execute(peticion_reporte)

        # print("Enviando alertas")
        # enviar_alertas(peticion_alerta)
        # con.guardar_analisis(peticion_proceso)

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
    numero_grafica = reporte_fuzzing(analisis, peticion_reporte, numero_grafica)
    numero_grafica = reporte_explotacion(analisis, peticion_reporte, numero_grafica)
    return "Consulta de reporte creado"
"""
    Modulos
"""
def enviar_fuzzing(peticion_proceso):
    for posicion_pagina in range(len(peticion_proceso["analisis"]["paginas"])):
        json_fuzzing = {
            "url":peticion_proceso["analisis"]["paginas"][posicion_pagina]["pagina"],
            "hilos":4,
            "cookie":peticion_proceso["cookie"]
        }
        forms = fuzzing.execute(json_fuzzing)
        peticion_proceso["analisis"]["paginas"][posicion_pagina].update(forms)

def enviar_explotacion(con, datos_identificados, datos_explotacion, peticion_proceso):
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
def enviar_alertas(peticion_alerta):
    alertas.execute(peticion_alerta)

def alertas_fuzzing(peticion_proceso, peticion_alerta):
    for posicion_pagina in range(len(peticion_proceso["analisis"]["paginas"])):
        fuzzing_alertas = fuzzing_obtener_alertas(peticion_proceso["analisis"]["paginas"][posicion_pagina])
        peticion_alerta["sitios"].append(fuzzing_alertas)        

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

    numero_grafica = crear_reportes_informacion(informacion_estadisticas, peticion_reporte, datos_host, numero_grafica)
    return numero_grafica

def reporte_analisis(peticion_proceso, peticion_reporte):
    analisis = {}
    analisis["servidor"] = analisis_obtener_servidor(peticion_proceso["analisis"]["servidor"]) # Nombre y versión
    analisis["cms"] = analisis_obtener_cms(peticion_proceso["analisis"]["cms"]) # Nombre y versión
    analisis["plugins"] = analisis_obtener_plugins(peticion_proceso["analisis"]["plugins"]) # Listado
    analisis["librerias"] = analisis_obtener_librerias(peticion_proceso["analisis"]["librerias"]) #  Listado
    analisis["archivos"] = analisis_obtener_archivos(peticion_proceso["analisis"]["archivos"]) # Listado
    analisis["vulnerabilidades"] = analisis_obtener_vulnerabilidades(peticion_proceso["analisis"]["vulnerabilidades"]) # Listado
    analisis["paginas"] = analisis_obtener_paginas(peticion_proceso["analisis"]["paginas"]) # Total
    analisis["frameworks"] = analisis_obtener_frameworks(peticion_proceso["analisis"]["frameworks"]) # Listado
    analisis["lenguajes"] = analisis_obtener_lenguajes(peticion_proceso["analisis"]["lenguajes"]) # Listado -> Nombre y versiones -> NNN VVV1,VVV2
    analisis["headers"] = analisis_obtener_headers(peticion_proceso["analisis"]["headers"]) # Listado

    crear_reportes_analisis(analisis, peticion_reporte)

#########
def analisis_obtener_cms(datos_cms):
    nombre = ""
    version = ""
    if "nombre" in datos_cms:
        nombre = datos_cms["nombre"]
    if "version" in datos_cms:
        version = datos_cms["version"]
    return [["{0}: {1}".format(nombre.capitalize(), version)]]

def analisis_obtener_plugins(datos_plugins): return [[plugin] for plugin in datos_plugins]

def analisis_obtener_librerias(datos_librerias): return [[libreria] for libreria in datos_librerias]

def analisis_obtener_archivos(datos_archivos): return [[archivo] for archivo in datos_archivos]

def analisis_obtener_vulnerabilidades(datos_vulnerabilidades): return [[vulnerabilidad] for vulnerabilidad in datos_vulnerabilidades]

def analisis_obtener_paginas(datos_paginas): return [[len(datos_paginas)]]

def analisis_obtener_frameworks(datos_frameworks): return [[framework] for framework in datos_frameworks]

def analisis_obtener_lenguajes(datos_lenguajes):
    nombre = ""
    version = "S/N"
    lenguajes = []

    for lenguaje in datos_lenguajes:
        if "nombre" in lenguaje:
            nombre = lenguaje["nombre"]
            if "version" in lenguaje:
                for numero_version in lenguaje["version"]:
                    version += numero_version + ", "
        lenguajes.append(["{0}: {1}".format(nombre.upper(), version)])
        version = "S/N"
    return lenguajes

def analisis_obtener_headers(datos_headers): return [[header] for header in datos_headers]

def analisis_obtener_servidor(datos_servidor):
    nombre = ""
    version = ""
    if "nombre" in datos_servidor:
        nombre = datos_servidor["nombre"]
    if "version" in datos_servidor:
        version = datos_servidor["version"]
    return [["{0}: {1}".format(nombre.capitalize(), version)]]

########

def reporte_fuzzing(peticion_proceso, peticion_reporte, numero_grafica):
    fuzzing_estadistica_general = []
    fuzzing_estadistica_individual = []
    paginas = len(peticion_proceso["analisis"]["paginas"])
    for posicion_pagina in range(paginas):
        fuzzing_estadistica_individual.append(fuzzing_obtener_estaditisticas(peticion_proceso["analisis"]["paginas"][posicion_pagina]))
    
    for individual in fuzzing_estadistica_individual:
        xss =+ individual[1]
        sqli =+ individual[2]
        lfi =+ individual[3]

    fuzzing_estadistica_general.append(peticion_proceso["sitio"])
    fuzzing_estadistica_general.append(xss)
    fuzzing_estadistica_general.append(sqli)
    fuzzing_estadistica_general.append(lfi)
    numero_grafica = crear_reportes_fuzzing(fuzzing_estadistica_general, fuzzing_estadistica_individual, peticion_reporte, numero_grafica)
        
    return numero_grafica

def reporte_explotacion(peticion_proceso, peticion_reporte, numero_grafica):
    explotacion_estadisticas = explotacion_obtener_estadisticas(peticion_proceso)
    numero_grafica = crear_reportes_explotacion(explotacion_estadisticas,peticion_reporte, numero_grafica)
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
def fuzzing_datos_generales(fuzzing_estadisticas,reporte):
    xss = fuzzing_estadisticas[0][1]
    sqli = fuzzing_estadisticas[0][2]
    lfi = fuzzing_estadisticas[0][3]
    ataques = ["XSS","SQLi","LFI"]

    fuzzing_diagrama = go.Figure(data=[go.Pie(labels=ataques, values=[xss,sqli,lfi])])
    fuzzing_diagrama.write_html(reporte, full_html=False, include_plotlyjs="cdn")

# Explotacion
def explotacion_datos_generales(explotacion_estadisticas,reporte):
    exito = 0
    fracaso = 0
    inconcluso = 0
    ataques = ["Exito","Fracaso","Inconcluso"]
    for explotacion in explotacion_estadisticas:
        if "sitio" == explotacion:
            continue
        exito += explotacion_estadisticas[explotacion]["exitoso"]
        fracaso += explotacion_estadisticas[explotacion]["fracaso"]
        inconcluso += explotacion_estadisticas[explotacion]["inconcluso"]
    ataques_resultado = [exito, fracaso, inconcluso]
    fuzzing_diagrama = go.Figure(data=[go.Pie(labels=ataques, values=ataques_resultado)])
    
    fuzzing_diagrama.write_html(reporte, full_html=False, include_plotlyjs="cdn")
    return ataques, ataques_resultado

"""
    Crear reportes
"""
# Informacion
def crear_reportes_informacion_individual_dns(registros, registros_etiqueta, reporte, sitio):
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

def crear_reportes_informacion_individual_puertos(puertos, puertos_estado, reporte, sitio):
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

def crear_reportes_informacion_general(datos_host):
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

def crear_reportes_informacion(informacion_estadisticas, peticion_reporte, datos_host, numero_grafica):
    reporte = root+"/modules/reportes/ifram_grafica_info"
    
    analisis = crear_reportes_informacion_general(datos_host)
    peticion_reporte["analisis"].append(analisis)

    puertos, puertos_estado = informacion_datos_individuales_puertos(informacion_estadisticas,reporte+"{0}.html".format(numero_grafica))
    analisis = crear_reportes_informacion_individual_puertos(puertos, puertos_estado,reporte+"{0}.html".format(numero_grafica),peticion_reporte["sitio"])
    peticion_reporte["analisis"].append(analisis)
    numero_grafica += 1
    
    puertos, puertos_estado = informacion_datos_individuales_dns(informacion_estadisticas,reporte+"{0}.html".format(numero_grafica))
    analisis = crear_reportes_informacion_individual_dns(puertos, puertos_estado,reporte+"{0}.html".format(numero_grafica),peticion_reporte["sitio"])
    peticion_reporte["analisis"].append(analisis)
    numero_grafica += 1
    return numero_grafica

# Analisis
def crear_reportes_analisis_general(datos_analisis):
    analisis = []
    for categoria in datos_analisis:
        datos = datos_analisis[categoria]
        analisis_individual = {
                    "categoria":"Analisis",
                    "titulo":categoria.capitalize(),
                    "grafica":"",
                    "cabecera":["Nombre"],
                    "datos":datos
        }
        analisis.append(analisis_individual)
    return analisis

def crear_reportes_analisis(datos_analisis, peticion_reporte):
    analisis = crear_reportes_analisis_general(datos_analisis)
    for valor in analisis:
        peticion_reporte["analisis"].append(valor)

# Fuzzing
def crear_reporte_fuzzing_general(fuzzing_estadistica_general, reporte):
    analisis = {
                "categoria":"Fuzzing",
                "titulo":"Resultados generales",
                "grafica":reporte,
                "cabecera":["Sitio","XSS","SQLi","LFI"],
                "datos":[fuzzing_estadistica_general]
    }
    return analisis

def crear_reporte_fuzzing_individual(fuzzing_estadistica_individual):
    analisis = {
                "categoria":"Fuzzing",
                "titulo":"Resultados individuales",
                "grafica":"",
                "cabecera":["Página","XSS","SQLi","LFI"],
                "datos":fuzzing_estadistica_individual
    }
    return analisis

def crear_reportes_fuzzing(fuzzing_estadistica_general, fuzzing_estadistica_individual, peticion_reporte, numero_grafica):
    reporte = root+"/modules/reportes/ifram_grafica"

    fuzzing_datos_generales(fuzzing_estadistica_general,reporte+"{0}.html".format(numero_grafica))
    analisis = crear_reporte_fuzzing_general(fuzzing_estadistica_general, reporte+"{0}.html".format(numero_grafica))
    peticion_reporte["analisis"].append(analisis)
    numero_grafica += 1
    
    analisis = crear_reporte_fuzzing_individual(fuzzing_estadistica_individual)
    peticion_reporte["analisis"].append(analisis)

    numero_grafica += 1
    return numero_grafica

# Explotacion
def crear_reporte_explotacion_general(ataques, ataques_resultado, reporte, sitio):
    analisis = {
                "categoria":"Explotacion",
                "titulo":"Resultados generales",
                "grafica":reporte,
                "cabecera":["Sitio","Motivo","Estado"],
                "datos":[
                    [sitio,"Exploits exitosos: {0}".format(ataques_resultado[0]),ataques[0]],
                    [sitio,"Exploits no exitosos: {0}".format(ataques_resultado[1]),ataques[1]],
                    [sitio,"Exploits inconclusas: {0}".format(ataques_resultado[2]),ataques[2]]]
    }
    return analisis

def crear_reportes_explotacion(explotacion_estadisticas, peticion_reporte, numero_grafica):
    reporte = root+"/modules/reportes/ifram_grafica_explotacion"
    ataques, ataques_resultado = explotacion_datos_generales(explotacion_estadisticas,reporte+"{0}.html".format(numero_grafica))
    analisis = crear_reporte_explotacion_general(ataques,ataques_resultado,reporte+"{0}.html".format(numero_grafica),peticion_reporte["sitio"])
    peticion_reporte["analisis"].append(analisis)
    numero_grafica += 1
    return numero_grafica

"""
    Utilidades
        Falta obtener los datos para consultar los exploits, estos se recuperan del analisis y obtener informacion
"""
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
    datos_identificados["cms"].extend(obtener_cms_version_unica(peticion_proceso["analisis"], "plugins", cms_nombre))
    
    if "vulnerabilidades" in peticion_proceso["analisis"]:
        for cve in peticion_proceso["analisis"]["vulnerabilidades"]:
            datos_identificados["cve"].append(cve)

    datos_identificados["profundidad"] = peticion_proceso["profundidad"]

    datos_explotacion = {"sitio":peticion_proceso["sitio"],"puertos":["80"]}
    # for puerto in peticion_proceso["informacion"]["Puertos"]["abiertos"]:
    #     datos_explotacion["puertos"].append(puerto["puerto"])

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
    print(exploits)
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

def fuzzing_obtener_estaditisticas(forms):
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

def fuzzing_obtener_alertas(forms):
    forms_alertas = {}
    forms_alertas["pagina"] = forms["pagina"]
    motivo = ""
    for form in forms["forms"]:
        xss = 0
        sqli = 0
        lfi = 0
        for index in forms["forms"][form]:
            if index["xss"] == True:
                xss += 1
            if index["sqli"] == True:
                sqli += 1
            if index["lfi"] == True:
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

def explotacion_obtener_estadisticas(explotaciones):
    explotacion = {}
    for exploit in explotaciones["explotaciones"]:
        explotacion[exploit] = {
            "exitoso":0,
            "fracaso":0,
            "inconcluso":0}
        for puerto in explotaciones["explotaciones"][exploit]:
            if explotaciones["explotaciones"][exploit][puerto] == 1:
                explotacion[exploit]["exitoso"] += 1
            if explotaciones["explotaciones"][exploit][puerto] == 0:
                explotacion[exploit]["inconcluso"] += 1
            if explotaciones["explotaciones"][exploit][puerto] == -1:
                explotacion[exploit]["fracaso"] += 1
    return explotacion

@app.route("/")
def index():
    return render_template("app.html")

@app.route("/ejecucion",methods=["GET","POST"])
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