# Importaciones
## Flask
import re
from flask import Flask, render_template, request
from flask_cors import CORS

## Utileria
from base64 import decode, encode
from os import path
from datetime import datetime
import plotly.graph_objects as go

## Modulos
from modules.obtencion_informacion import obtener_informacion
from modules.alertas import alertas
#from modules.analisis import analisis
from modules.exploits import exploits
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

    peticion_proceso = {
        "sitio":peticion["sitio"],
        "ejecucion":"",
        "informacion":{
            "":""
        },
        "analisis":{
            "":""
        },
        "paginas":[
        ],
        "cookie":"PHDSESSID:jnj8mr8fugu61ma86p9o96frv0",
        "estado":{
            "fecha":datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
        }
    }

    if peticion["ejecucion"] != "":
        programacion.execute(peticion)
        return "True"
    else:
        ############################################################# OBTENER INFORMACION #############################################################
        """ 
            Obtener informacion
            Estado : En desarrollo
            Errores:
                DNSDumpster:
                    *List index out of range
                Robtex:
                    429 error retrieving https://freeapi.robtex.com/ipquery/132.248.124.130: {"status":"ratelimited"}:
                        TypeError: 'NoneType' object is not subscriptable
                Google:
                    No da resultados
            Errores menores:
                DNSDumpster:
                    Se repiten los resultados en varias ocasiones
                Robtex:
                    Se repiten los resultados en varias ocasiones                
        """
        # respuesta_obtener_informacion = obtener_informacion.execute(peticion)
        # print(respuesta_obtener_informacion)
        ############################################################# ANALISIS #############################################################
        """
            Analisis
            Estado : En desarrollo
        """
        # respuesta_analisis = analisis.execute(peticion_json)
        # print(respuesta_analisis)
        ############################################################# FUZZING #############################################################
        """
            Fuzzing
            Estado : En desarrollo
            Errores :
                Falta hacer bypass 

            Errores menores:
        """
        peticion_proceso = {
            "sitio":peticion["sitio"],
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
                "CMS":{
                    "nombre":"drupal",
                    "version":"7.57"
                },
                "Servidor":{
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
                ]
            },
            "paginas":[
                {
                    "sitio":"https://xss-game.appspot.com/level1",
                }
            ],
            "cookie":peticion["cookie"],
            "estado":{
                "fecha":datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
            }
        }

        peticion_reporte = {
            "sitio":peticion_proceso["sitio"],
            "fecha":peticion_proceso["estado"]["fecha"],
            "analisis":[],
        }

        numero_grafica = 0

        numero_grafica = reporte_fuzzing(con, peticion_proceso, peticion_reporte, numero_grafica)
        
        ############################################################# EXPLOTACION #############################################################

        #datos_explotacion, datos_identificados = obtener_datos_consulta_exploits(peticion_proceso)

        datos_explotacion = {
            "sitio":"altoromutual.com:8080",
            "puertos": ["22","445","497"],
            #"pagina": ["http://www.altoromutual.com:8080/login.jsp","http://www.altoromutual.com:8080/search.jsp"],
        }

        datos_identificados = {
            "software":[
                {
                    "software_nombre":"Apache",
                    "software_version":"1.12"
                },
                {
                    "software_nombre":"Drupal",
                    "software_version":"7.57"
                }
            ],
            "cms":[
                {
                    "cms_nombre":"Drupal",
                    "cms_categoria":"Plugin",
                    "cms_extension_nombre":"Form 7",
                    "cms_extension_version":"1.12"
                },
                {
                    "cms_nombre":"Wordpress",
                    "cms_categoria":"Plugin",
                    "cms_extension_nombre":"",
                    "cms_extension_version":""
                }
            ],
            "profundidad":2
        }

        numero_grafica = reporte_explotacion(con, datos_explotacion, datos_identificados, peticion_proceso, peticion_reporte, numero_grafica)
        ############################################################# CONSULTA #############################################################

        con.guardar_analisis(peticion_proceso)

        informacion = obtener_informacion_sitio(con, peticion_proceso["sitio"])

        analisis = obtener_informacion_analisis(con, peticion_proceso["sitio"])

        fuzzings = obtener_informacion_fuzzing(con, peticion_proceso["sitio"])

        explotaciones = obtener_informacion_explotacion(con, peticion_proceso["sitio"])

        return "True"
"""
    Reportes
"""
def reporte_fuzzing(con, peticion_proceso, peticion_reporte, numero_grafica):
    for posicion_pagina in range(len(peticion_proceso["paginas"])):
        json_fuzzing = {
            "url":peticion_proceso["paginas"][posicion_pagina]["sitio"],
            "hilos":4,
            "cookie":peticion_proceso["cookie"]
        }
        forms = fuzzing.execute(json_fuzzing)
        peticion_proceso["paginas"][posicion_pagina].update(forms)
        con.fuzzing_insertar_datos(peticion_proceso["paginas"][posicion_pagina])
        fuzzing_estadisticas = con.fuzzing_obtener_estaditisticas()
        con.fuzzing_borrar_temp()
        numero_grafica = crear_reportes_fuzzing(fuzzing_estadisticas, peticion_reporte, numero_grafica)
    return numero_grafica

def reporte_explotacion(con, datos_explotacion, datos_identificados, peticion_proceso, peticion_reporte, numero_grafica):
    exploits = buscar_exploits(datos_identificados, con)
    explotaciones = explotacion.execute(datos_explotacion,exploits)
    peticion_proceso.update(explotaciones)
    con.explotacion_insertar_datos(peticion_proceso)
    explotacion_estadisticas = con.explotacion_obtener_estadisticas()
    con.explotacion_borrar_temp()
    numero_grafica = crear_reportes_explotacion(explotacion_estadisticas,peticion_reporte, numero_grafica)
    reportes.execute(peticion_reporte)
    return numero_grafica

"""
    Generar reportes
"""
# Fuzzing
def fuzzing_datos_generales(fuzzing_estadisticas,reporte):
    exito = 0
    total = 0
    ataques = ["Exito","Totales"]
    for form in fuzzing_estadisticas:
        if "sitio" == form:
            continue
        for ataque in fuzzing_estadisticas[form]:
            exito += fuzzing_estadisticas[form][ataque]["exitoso"]
        
        total += fuzzing_estadisticas[form]["xss"]["exitoso"] + fuzzing_estadisticas[form]["xss"]["fracaso"]

    ataques_resultado = [exito, total]
    fuzzing_diagrama = go.Figure(data=[go.Pie(labels=ataques, values=ataques_resultado)])
    fuzzing_diagrama.write_html(reporte, full_html=False, include_plotlyjs="cdn")
    return ataques, ataques_resultado

def fuzzing_datos_individuales(fuzzing_estadisticas,reporte):
    lista_resultados_exitosos = [0,0,0]
    total = [0,0,0]
    for form in fuzzing_estadisticas:
        if "sitio" == form:
            continue
        for ataque in fuzzing_estadisticas[form]:
            if ataque == "xss":
                lista_resultados_exitosos[0] += fuzzing_estadisticas[form][ataque]["exitoso"]
                total[0] += fuzzing_estadisticas[form][ataque]["fracaso"] + fuzzing_estadisticas[form][ataque]["exitoso"]
            if ataque == "sqli":
                lista_resultados_exitosos[1] += fuzzing_estadisticas[form][ataque]["exitoso"]
                total[1] += fuzzing_estadisticas[form][ataque]["fracaso"] + fuzzing_estadisticas[form][ataque]["exitoso"]
            if ataque == "lfi":
                lista_resultados_exitosos[2] += fuzzing_estadisticas[form][ataque]["exitoso"]
                total[2] += fuzzing_estadisticas[form][ataque]["fracaso"] + fuzzing_estadisticas[form][ataque]["exitoso"]
    ataques = ["XSS","SQLi","LFI"]
    fuzzing_diagrama = go.Figure(data=[
        go.Bar(name="Exitoso", x=ataques, y=lista_resultados_exitosos),
        go.Bar(name="Totales", x=ataques, y=total)
    ])
    fuzzing_diagrama.update_layout(barmode='group')
    
    fuzzing_diagrama.write_html(reporte, full_html=False, include_plotlyjs="cdn")
    return ["Exitoso","Fracaso"], ataques, lista_resultados_exitosos, total

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
# Fuzzing
def crear_reporte_fuzzing_general(ataques, ataques_resultado, reporte, sitio):
    analisis = {
                "categoria":"Fuzzing",
                "titulo":"Resultados generales",
                "grafica":reporte,
                "cabecera":["Sitio","Motivo","Estado"],
                "datos":[
                    [sitio,"Número de peticiones exitosas: {0}".format(ataques_resultado[0]),ataques[0]],
                    [sitio,"Número de peticiones totales: {0}".format(ataques_resultado[1]),ataques[1]]]
    }
    return analisis

def crear_reporte_fuzzing_individual(lista_resultados_exitosos, lista_resultados_fracasos, reporte, sitio):
    analisis = {
                "categoria":"",
                "titulo":"Resultados individuales",
                "grafica":reporte,
                "cabecera":["Sitio","Motivo","Estado"],
                "datos":[
                    [sitio,"Número de peticiones exitosas XSS: {0}".format(lista_resultados_exitosos[0]),"Exito"],
                    [sitio,"Número de peticiones totales XSS: {0}".format(lista_resultados_fracasos[0]),"Totales"],
                    [sitio,"Número de peticiones exitosas SQLi: {0}".format(lista_resultados_exitosos[1]),"Exito"],
                    [sitio,"Número de peticiones totales SQLi: {0}".format(lista_resultados_fracasos[1]),"Totales"],
                    [sitio,"Número de peticiones exitosas LFI: {0}".format(lista_resultados_exitosos[2]),"Exito"],
                    [sitio,"Número de peticiones totales LFI: {0}".format(lista_resultados_fracasos[2]),"Totales"]]
    }
    return analisis

def crear_reportes_fuzzing(fuzzing_estadisticas, peticion_reporte, numero_grafica):
    reporte = root+"/modules/reportes/ifram_grafica"
    ataques, ataques_resultado = fuzzing_datos_generales(fuzzing_estadisticas,reporte+"{0}.html".format(numero_grafica))
    analisis = crear_reporte_fuzzing_general(ataques,ataques_resultado,reporte+"{0}.html".format(numero_grafica),fuzzing_estadisticas["sitio"])
    peticion_reporte["analisis"].append(analisis)
    numero_grafica += 1
    estado, ataques, lista_resultados_exitosos, lista_resultados_fracasos = fuzzing_datos_individuales(fuzzing_estadisticas,reporte+"{0}.html".format(numero_grafica))
    analisis = crear_reporte_fuzzing_individual(lista_resultados_exitosos, lista_resultados_fracasos,reporte+"{0}.html".format(numero_grafica),fuzzing_estadisticas["sitio"])
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
                    [sitio,"Número de peticiones exitosas: {0}".format(ataques_resultado[0]),ataques[0]],
                    [sitio,"Número de peticiones sin exito: {0}".format(ataques_resultado[1]),ataques[1]],
                    [sitio,"Número de peticiones inconclusas: {0}".format(ataques_resultado[2]),ataques[2]]]
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
    return True, True

def buscar_exploits(datos_identificados, con):
    exploits = []
    for software in datos_identificados["software"]:
        json_software = {
            "software_nombre":software["software_nombre"],
            "software_version":software["software_version"],
        }
        exploit_software = con.exploit_buscar_software(json_software,datos_identificados["profundidad"])
        for exploit in exploit_software["exploits"]:
            exploits.append(exploit)
    
    for cms in datos_identificados["cms"]:
        json_cms = {
            "cms_nombre":cms["cms_nombre"],
            "cms_categoria":cms["cms_categoria"],
            "cms_extension_nombre":cms["cms_extension_nombre"],
            "cms_extension_version":cms["cms_extension_version"]
        }
        exploit_cms = con.exploit_buscar_cms(json_cms,datos_identificados["profundidad"])
        for exploit in exploit_cms["exploits"]:
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
    Programar tarea
        Ejecucion
"""

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

# @app.route("/consulta", methods=["GET","POST"])
# def consulta():
#     if request.method == "POST":
#         peticion_json = request.get_json()
#         validar_json_consulta(peticion_json)
#         respuesta = consulta.execute(peticion_json)
#         print(respuesta)
#         return respuesta

# @app.route("/exploits", methods=["GET","POST"])
# def exploits():
#     if request.method == "POST":
#         peticion_json = request.get_json()
#         validar_json_exploit(peticion_json)    
#         respuesta = exploits.execute(peticion_json)
#         print(respuesta)
#         return respuesta

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