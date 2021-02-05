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
#from modules.consulta import consulta
from modules.exploits import exploits
from modules.explotacion import explotacion
from modules.fuzzing import fuzzing
from modules.modelo.conector import Conector
from modules.reportes import reportes
from modules.estadisticas import estadisticas
#from modules.ejecucion import ejecucion

root = path.abspath(path.dirname(__file__))
app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = 'datosrandomjamasvistos'

'''
    Modo de ejecucion:
        
        Ejecucion -> Obtener_informacion -> Análisis [Ejecucion de Fuzzing[Hilos] -> Lista de vulnerabilidades y Lista de posibles vulnerabilidades]
            -> Identificacion -> Explotacion [-> Lista de vulnerabilidades, Lista de posibles vulnerabilidades y Lista de Fracasos]
                -> Reporte

        Base de exploits
        Consulta
'''

def iniciar_analisis(peticion_json):
    con = Conector()
    ############################################################# OBTENER INFORMACION #############################################################
    ''' 
        Obtener informacion
        Estado : En desarrollo
        Errores:
            DNSDumpster:
                List index out of range
            Robtex:
                429 error retrieving https://freeapi.robtex.com/ipquery/132.248.124.130: {"status":"ratelimited"}:
                    TypeError: 'NoneType' object is not subscriptable
            Google:
                No da resultados
            Bing:
                No da resultados
            IPV4Info:
                No da resultados
        Errores menores:
            DNSDumpster:
                Se repiten los resultados en varias ocasiones
            Robtex:
                Se repiten los resultados en varias ocasiones                
    '''
    # respuesta_obtener_informacion = obtener_informacion.execute(peticion_json)
    # print(respuesta_obtener_informacion)
    ############################################################# ANALISIS #############################################################
    '''
        Analisis
        Estado : Por desarrollar
    '''
    # respuesta_analisis = analisis.execute(peticion_json)
    # print(respuesta_analisis)
    '''
        Fuzzing
        Estado : En desarrollo
        Errores : 

        Errores menores:
    '''
    ############################################################# FUZZING #############################################################
    # json_fuzzing = {
    #     "url":"http://www.altoromutual.com:8080/login.jsp",
    #     "hilos":4,
    #     "cookie":"PHDSESSID:jnj8mr8fugu61ma86p9o96frv0"
    # }
    # respuesta_fuzzing = fuzzing.execute(json_fuzzing)
    # con = Conector()
    # con.fuzzing_insertar_datos(respuesta_fuzzing)
    json_recibido = {
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
                #"forms":[{}]
            }
        ],
        "cookie":"PHDSESSID:jnj8mr8fugu61ma86p9o96frv0",
        "estado":{
            "fecha":""
        }
        #"Explotacion":[{}]
    }

    json_reporte = {
        "sitio":"seguridad.unam.mx",
        "fecha":datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
        "analisis":[],
    }

    numero_grafica = 0

    for posicion_pagina in range(len(json_recibido["paginas"])):
        json_fuzzing = {
            "url":json_recibido["paginas"][posicion_pagina]["sitio"],
            "hilos":4,
            "cookie":json_recibido["cookie"]
        }
        forms = fuzzing.execute(json_fuzzing)
        json_recibido["paginas"][posicion_pagina].update(forms)
        con.fuzzing_insertar_datos(json_recibido["paginas"][posicion_pagina])
        fuzzing_estadisticas = con.fuzzing_obtener_estaditisticas()
        con.fuzzing_borrar_temp()
        numero_grafica = crear_reportes_fuzzing(fuzzing_estadisticas, json_reporte, numero_grafica)
    
    ############################################################# EXPLOTACION #############################################################

    json_explotacion, json_identificar = obtener_datos_consulta_exploits(json_recibido)

    json_explotacion = {
        "sitio":"altoromutual.com:8080",
        "puertos": ["22","445","497"],
        #"pagina": ["http://www.altoromutual.com:8080/login.jsp","http://www.altoromutual.com:8080/search.jsp"],
    }

    json_identificar = {
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


    exploits = buscar_exploits(json_identificar, con)
    explotaciones = explotacion.execute(json_explotacion,exploits)
    json_recibido["explotaciones"] = explotaciones
    con.explotacion_insertar_datos(json_recibido["explotaciones"])
    explotacion_estadisticas = con.explotacion_obtener_estadisticas()
    con.explotacion_borrar_temp()
    crear_reportes_explotacion(explotacion_estadisticas,json_reporte, numero_grafica)
    reportes.execute(json_reporte)

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

def crear_reportes_fuzzing(fuzzing_estadisticas, json_reporte, numero_grafica):
    reporte = root+"/modules/reportes/ifram_grafica"
    ataques, ataques_resultado = fuzzing_datos_generales(fuzzing_estadisticas,reporte+"{0}.html".format(numero_grafica))
    analisis = crear_reporte_fuzzing_general(ataques,ataques_resultado,reporte+"{0}.html".format(numero_grafica),fuzzing_estadisticas["sitio"])
    json_reporte["analisis"].append(analisis)
    numero_grafica += 1
    estado, ataques, lista_resultados_exitosos, lista_resultados_fracasos = fuzzing_datos_individuales(fuzzing_estadisticas,reporte+"{0}.html".format(numero_grafica))
    analisis = crear_reporte_fuzzing_individual(lista_resultados_exitosos, lista_resultados_fracasos,reporte+"{0}.html".format(numero_grafica),fuzzing_estadisticas["sitio"])
    json_reporte["analisis"].append(analisis)
    numero_grafica += 1
    return numero_grafica

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

def crear_reportes_explotacion(explotacion_estadisticas, json_reporte, numero_grafica):
    reporte = root+"/modules/reportes/ifram_grafica_explotacion"
    ataques, ataques_resultado = explotacion_datos_generales(explotacion_estadisticas,reporte+"{0}.html".format(numero_grafica))
    analisis = crear_reporte_explotacion_general(ataques,ataques_resultado,reporte+"{0}.html".format(numero_grafica),json_reporte["sitio"])
    json_reporte["analisis"].append(analisis)
    numero_grafica += 1

def obtener_datos_consulta_exploits(json_recibido):
    return True, True

def buscar_exploits(json_identificar, con):
    exploits = []
    for software in json_identificar["software"]:
        json_software = {
            "software_nombre":software["software_nombre"],
            "software_version":software["software_version"],
        }
        exploit_software = con.exploit_buscar_software(json_software,json_identificar["profundidad"])
        for exploit in exploit_software["exploits"]:
            exploits.append(exploit)
    
    for cms in json_identificar["cms"]:
        json_cms = {
            "cms_nombre":cms["cms_nombre"],
            "cms_categoria":cms["cms_categoria"],
            "cms_extension_nombre":cms["cms_extension_nombre"],
            "cms_extension_version":cms["cms_extension_version"]
        }
        exploit_cms = con.exploit_buscar_cms(json_cms,json_identificar["profundidad"])
        for exploit in exploit_cms["exploits"]:
            exploits.append(exploit)

    return exploits

@app.route("/")
def index():
    return render_template("app.html")

# @app.route("/ejecucion",methods=["GET","POST"])
# def ejecucion():
#     if request.method == "POST":
#         peticion_json = request.get_json()
#         validar_json_ejecucion(peticion_json)
#         iniciar_analisis(peticion_json)
#         print(respuesta)
#         return respuesta

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

# @app.route("/programar",methods=["GET","POST"])
# def programar():
#     if request.method == "POST":
#         peticion_json = request.get_json()
#         validar_json_programar(peticion_json)
#         respuesta = programar.execute(peticion_json)
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

peticion = {
	"sitio":"http://seguridad.unam.mx",
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
	}
}

if __name__ == "__main__":
    iniciar_analisis(peticion)
    app.run(host='127.0.0.1', port=3000, debug=True)