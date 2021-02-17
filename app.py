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
import json

## Modulos
from modules.obtencion_informacion import obtener_informacion
from modules.alertas import alertas
#from modules.analisis import analisis
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
            "fecha":datetime.now().strftime("%d/%m/%Y %H:%M:%S")
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
        ############################################################# OBTENER INFORMACION #############################################################

        reporte_informacion(peticion, peticion_proceso, peticion_reporte, numero_grafica)
        ############################################################# ANALISIS #############################################################

        # respuesta_analisis = analisis.execute(peticion_json)
        # print(respuesta_analisis)
        ############################################################# FUZZING #############################################################

        peticion_proceso["analisis"] = {
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
            }     
        peticion_proceso["paginas"] =[
                {
                    "sitio":"http://www.altoromutual.com:8080/login.jsp",
                },
                {
                    "sitio":"http://www.altoromutual.com:8080/search.jsp",
                }
            ]

        print("Iniciando Fuzzing")
        numero_grafica = reporte_fuzzing(peticion_proceso, peticion_reporte, peticion_alerta, numero_grafica)
        ############################################################# EXPLOTACION #############################################################

        #datos_explotacion, datos_identificados = obtener_datos_consulta_exploits(peticion_proceso)

        datos_explotacion = {
            "sitio":peticion_proceso["sitio"],
            "puertos": ["22","445","497"]
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
            "cve":[
              "CVE-2018-123","CVE-2019-5551","CVE-2007-4751"  
            ],
            "profundidad":2
        }

        print("Iniciando Explotacion")
        numero_grafica = reporte_explotacion(con, datos_explotacion, datos_identificados, peticion_proceso, peticion_reporte, peticion_alerta, numero_grafica)
        ############################################################# ALERTAS #############################################################
        
        print("Enviando alertas")
        enviar_alertas(peticion_alerta)
        con.guardar_analisis(peticion_proceso)
        ############################################################# CONSULTA #############################################################

        # informacion = obtener_informacion_sitio(con, peticion_proceso["sitio"])
        # analisis = obtener_informacion_analisis(con, peticion_proceso["sitio"])
        # fuzzings = obtener_informacion_fuzzing(con, peticion_proceso["sitio"])
        # explotaciones = obtener_informacion_explotacion(con, peticion_proceso["sitio"])

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
"""
    Alertas
"""
def enviar_alertas(peticion_alerta):
    alertas.execute(peticion_alerta)
"""
    Reportes
"""
def reporte_informacion(peticion, peticion_proceso, peticion_reporte, numero_grafica):
    respuesta_obtener_informacion = obtener_informacion.execute(peticion)
    peticion_proceso["informacion"] = respuesta_obtener_informacion

    datos_host = {}
    datos_host["host"] = peticion_proceso["informacion"]["Dnsdumpster"]["host"][0]["dominio"]
    datos_host["ip"] = peticion_proceso["informacion"]["Dnsdumpster"]["host"][0]["ip"]
    datos_host["dns_inverso"] = peticion_proceso["informacion"]["Dnsdumpster"]["host"][0]["dns_inverso"]
    datos_host["pais"] = peticion_proceso["informacion"]["Dnsdumpster"]["host"][0]["pais"]
    datos_host["cabecera"] = peticion_proceso["informacion"]["Dnsdumpster"]["host"][0]["cabecera"]

    informacion_estadisticas = informacion_obtener_estadisticas(peticion_proceso)

    numero_grafica = crear_reportes_informacion(informacion_estadisticas, peticion_reporte, datos_host, numero_grafica)
    return numero_grafica

def reporte_fuzzing(peticion_proceso, peticion_reporte, peticion_alerta, numero_grafica):
    for posicion_pagina in range(len(peticion_proceso["paginas"])):
        json_fuzzing = {
            "url":peticion_proceso["paginas"][posicion_pagina]["sitio"],
            "hilos":4,
            "cookie":peticion_proceso["cookie"]
        }
        forms = fuzzing.execute(json_fuzzing)
        peticion_proceso["paginas"][posicion_pagina].update(forms)
        fuzzing_estadisticas = fuzzing_obtener_estaditisticas(peticion_proceso["paginas"][posicion_pagina])
        fuzzing_alertas = fuzzing_obtener_alertas(peticion_proceso["paginas"][posicion_pagina])
        peticion_alerta["sitios"].append(fuzzing_alertas)        
        numero_grafica = crear_reportes_fuzzing(fuzzing_estadisticas, peticion_reporte, numero_grafica)
        
    return numero_grafica

def reporte_explotacion(con, datos_explotacion, datos_identificados, peticion_proceso, peticion_reporte, peticion_alerta, numero_grafica):
    exploits = buscar_exploits(datos_identificados, con)
    if len(exploits) != 0:
        exploits = list({(e["ruta"],e["lenguaje"]):e for e in exploits}.values())
        explotaciones = explotacion.execute(datos_explotacion,exploits)
        peticion_proceso.update(explotaciones)
        explotacion_estadisticas = explotacion_obtener_estadisticas(peticion_proceso)
        explotacion_alertas = explotacion_obtener_alertas(peticion_proceso)
        peticion_alerta["sitios"].append(explotacion_alertas)
        numero_grafica = crear_reportes_explotacion(explotacion_estadisticas,peticion_reporte, numero_grafica)
    else:
        peticion_proceso.update({"explotaciones":{}})
    print("Creando el reporte")
    reportes.execute(peticion_reporte)
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
                    [sitio,"Exploits exitosos: {0}".format(ataques_resultado[0]),ataques[0]],
                    [sitio,"Exploits fracasados?: {0}".format(ataques_resultado[1]),ataques[1]],
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

    for cve in datos_identificados["cve"]:
        exploit_cve = con.exploit_buscar_cve(cve)
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

def fuzzing_obtener_estaditisticas(forms):
    forms_estadisticas = {}
    forms_estadisticas["sitio"] = forms["sitio"]
    for form in forms["forms"]:
        forms_estadisticas[form] = {
                "xss":{ "exitoso":0,
                        "fracaso":0},
                "sqli":{ "exitoso":0,
                        "fracaso":0},
                "lfi":{ "exitoso":0,
                        "fracaso":0}}
        for resultados in forms["forms"][form]:
            for ataque in ["xss","sqli","lfi"]:
                resultado_ataque = resultados[ataque]
                if resultado_ataque == True:
                    forms_estadisticas[form][ataque]["exitoso"] += 1
                else:
                    forms_estadisticas[form][ataque]["fracaso"] += 1
                    
    return forms_estadisticas

def fuzzing_obtener_alertas(forms):
    forms_alertas = {}
    forms_alertas["sitio"] = forms["sitio"]
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

@app.route("/exploits", methods=["GET","POST"])
def exploits():
    if request.method == "POST":
        peticion_json = request.get_json()
        #validar_json_exploit(peticion_json)    
        respuesta = guardar_exploit(peticion_json)
        return respuesta
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

# def fuzzing_obtener_alertas(self):
#     coleccion_fuzzing = self.base_datos[strings.COLECCION_FUZZING]
#     forms_alertas = {}
#     forms = coleccion_fuzzing.find_one()
#     forms_alertas["sitio"] = forms["sitio"]
#     motivo = ""
#     for form in forms["forms"]:
#         for index in forms["forms"][form]:
#             if index["xss"] == True:
#                 motivo += "XSS Detectado en Form -> {0}, inputs -> {1}\n".format(form, index["inputs"])
#             if index["sqli"] == True:
#                 motivo += "SQLi Detectado en Form -> {0}, inputs -> {1}\n".format(form, index["inputs"])
#             if index["lfi"] == True:
#                 motivo += "LFI Detectado en Form -> {0}, inputs -> {1}\n".format(form, index["inputs"])
#     forms_alertas["motivo"] = motivo
#     forms_alertas["estado"] = "Posiblemente vulnerable"
#     return forms_alertas

if __name__ == "__main__":
    app.run(host='127.0.0.1', port=3000, debug=True)

    