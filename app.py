# Importaciones
## Flask
from weakref import ProxyTypes
from flask_cors.core import serialize_option
from modules.strings import COLECCION_ANALISIS
import re
from flask import Flask, render_template, request
from flask_cors import CORS

## Utileria
from base64 import decode, encode
from os import path, remove, mkdir
import plotly.express as px
from datetime import datetime
import plotly.graph_objects as go
import json
from time import sleep, time
import requests
import threading

## Modulos
from modules.obtencion_informacion import obtener_informacion as obtener_informacion
from modules.alertas import alertas
from modules.analisis import analisis
from modules.exploits import exploits as exp
from modules.explotacion import explotacion
from modules.fuzzing2 import fuzzing
from modules.modelo.conector import Conector
from modules.reportes import reportes
from modules.ejecucion import ejecucion as programacion

root = path.abspath(path.dirname(__file__))
app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = 'ojalaSePudieraLlorar_grasa'
'''
    Expresiones regulares
'''
# Detectar la versión
patron_version = r"^(\d+\.?\d*)"

'''
    Modo de ejecucion:
        
        Ejecucion -> Obtener_informacion -> Análisis [Ejecucion de Fuzzing[Hilos] -> Lista de vulnerabilidades y Lista de posibles vulnerabilidades]
            -> Identificacion -> Explotacion [-> Lista de vulnerabilidades, Lista de inconclusos y Lista de Fracasos]


        Base de exploits
        Consulta
        Reportes
'''

'''
    Funciones de controlador
'''
def ejecucion_analisis(peticion):
    con = Conector()

    if peticion["fecha"] != "":
        programacion.execute(peticion)
        return "Análisis programado"
    else:
        peticion_proceso = {
            "sitio":peticion["sitio"],
            "cookie":peticion["cookie"],
            "fecha":datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
            "profundidad":peticion["profundidad"],
            "redireccionamiento":peticion["redireccionamiento"],
            "lista_negra":peticion["lista_negra"],
            "analisis":{"paginas":[]}
        }

        peticion_reporte = {
            "sitio":peticion_proceso["sitio"],
            "fecha":peticion_proceso["fecha"],
            "analisis":[],
        }

        peticion_alerta = {
            "subject":"Análisis del sitio \"{0}\" finalizado".format(peticion_proceso["sitio"]),
            "paginas":[],
            "fecha":datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
        }

        
        # print("Iniciando Información")
        # execute_informacion(peticion, peticion_proceso)

        # print("Iniciando Análisis")
        # execute_analisis(peticion_proceso)

        print("Iniciando Fuzzing")
        # peticion_proceso["analisis"]["paginas"] = [{"pagina":"https://localhost/drupal7/","forms":{}}]
        # peticion_proceso["analisis"]["paginas"] = [{"pagina":"https://seguridad.unam.mx/","forms":{}}]
        # peticion_proceso["analisis"]["paginas"] = [{"pagina":"https://localhost/DVWA-master/logout.php","forms":{}}]
        peticion_proceso["analisis"]["paginas"] = [
        {'pagina': 'http://localhost/DVWA-master/vulnerabilities/brute/'}, {'pagina': 'http://localhost/DVWA-master/vulnerabilities/csrf/'}, {'pagina': 'http://localhost/DVWA-master/vulnerabilities/fi/.?page=include.php'}, {'pagina': 'http://localhost/DVWA-master/vulnerabilities/upload/'}, {'pagina': 'http://localhost/DVWA-master/vulnerabilities/captcha/'}, {'pagina': 'http://localhost/DVWA-master/vulnerabilities/sqli/'}, {'pagina': 'http://localhost/DVWA-master/vulnerabilities/sqli_blind/'},  {'pagina': 'http://localhost/DVWA-master/vulnerabilities/xss_d/'}, {'pagina': 'http://localhost/DVWA-master/vulnerabilities/xss_r/'}, {'pagina': 'http://localhost/DVWA-master/vulnerabilities/xss_s/'}, {'pagina': 'http://localhost/DVWA-master/vulnerabilities/csp/'}, {'pagina': 'http://localhost/DVWA-master/vulnerabilities/javascript/'}
        ]
        # peticion_proceso["analisis"]["paginas"] = [
        #    {'pagina': 'http://localhost/DVWA-master/vulnerabilities/xss_d/'}, {'pagina': 'http://localhost/DVWA-master/vulnerabilities/sqli_blind/'}
        # ]
        execute_fuzzing(peticion_proceso, peticion_alerta)

        # print("Iniciando Explotacion")
        # execute_explotacion(con, peticion_proceso, peticion_alerta)

        # print("Iniciando Reporte")
        # execute_reporte(peticion_reporte)

        # print("Enviando alertas")
        # execute_alerta(peticion_alerta)
        
        print("Guardando analisis")
        con.guardar_analisis(peticion_proceso)

        return "Reporte generado"

def consulta_peticion_volcado():
    con = Conector()
    consulta = {}
    analisis_totales = con.obtener_analisis_totales()
    ultima_fecha = con.obtener_ultima_fecha()
    analisis = con.obtener_analisis_generales()

    consulta["analisis_totales"] = analisis_totales
    consulta["ultima_fecha"] = ultima_fecha
    consulta["analisis"] = analisis
    respueta_json = json.dumps(consulta)
    return respueta_json

def consulta_peticion_reporte(peticion):
    con = Conector()
    analisis = con.obtener_analisis(peticion)
    if analisis is not None:
        peticion_reporte = {
            "sitio":analisis["sitio"],
            "fecha":analisis["fecha"],
            "analisis":[],
        }

    execute_reporte(analisis, peticion_reporte)
    return json.dumps({"estado":"error"})

def exploits_peticion_crear(peticion):
    con = Conector()
    exploit = exp.execute(peticion)
    con.exploit_insertar_datos(exploit)
    return json.dumps({"estado":"ok"})

def exploits_peticion_volcado():
    con = Conector()
    volcado = con.exploit_volcado()
    if len(volcado["exploits"]) == 0:
        return json.dumps({"estado":"error"})
    return volcado

def exploits_peticion_editar(peticion_json):
    con = Conector()
    registro = con.exploit_consulta_registro(peticion_json)
    if registro == None:
        return json.dumps({"estado":"error"})
    return registro

def exploits_peticion_actualizar(peticion):
    con = Conector()
    exploit = exp.execute(peticion)
    con.exploit_actualizar_registro(exploit)
    return json.dumps({"estado":"ok"})

def exploits_peticion_eliminar(peticion_json):
    con = Conector()
    ruta = "./files/" + peticion_json["exploit"]
    try:
        remove(ruta)
    except FileNotFoundError:
        print("Exploit no encontrado")
    con.exploit_eliminar_registro(peticion_json)
    return json.dumps({"estado":"ok"})

def proximos_peticion_escaneos():
    pendientes = []
    peticion_actual = cola.get_peticion_actual()
    if len(peticion_actual) != 0:
        pendientes.append({"sitio":peticion_actual["sitio"],"fecha":peticion_actual["fecha"],"estado":"Actual"})
        peticiones = cola.get_peticiones()
        if len(peticiones) != 0:
            for peticion in peticiones:
                pendientes.append({"sitio":peticion["sitio"],"fecha":peticion["fecha"],"estado":"Pendiente"})
    else:
        pendientes.append({})
    return json.dumps(pendientes)
'''
    Estructura de la cola 
'''
class SingletonMeta(type):
   _instances = {}
   def __call__(cls, *args, **kwargs):
      if cls not in cls._instances:
         instance = super().__call__(*args, **kwargs)
         cls._instances[cls] = instance
      return cls._instances[cls]

class Encolamiento(metaclass=SingletonMeta):
    def __init__(self):
        self.peticion = []
        self.peticion_actual = {}

    def add_peticion(self, peticion):
        self.peticion.append(peticion)
        return "Peticion en cola"

    def pop_peticion(self):
        self.peticion_actual = self.peticion[0].copy()
        return self.peticion.pop(0)

    def len_peticion(self):
        return len(self.peticion)

    def get_peticiones(self):
        return self.peticion
    
    def get_peticion_actual(self):
        return self.peticion_actual

    def reset_peticion_actual(self):
        self.peticion_actual = {}

@app.before_first_request
def iniciar_ciclo_analisis():
    thread = threading.Thread(target=ciclo_analisis)
    thread.start()

def ciclo_analisis():
    while True:
        peticiones = cola.len_peticion()
        print("Obteniendo peticiones\nPeticiones en cola ->",peticiones)
        if peticiones > 0:
            peticion = cola.pop_peticion()
            # try:
            #     ejecucion_analisis(peticion)
            # except Exception as e:
            #     print("Ocurrió un error bro", e)
            ejecucion_analisis(peticion)
        cola.reset_peticion_actual()
        sleep(2)

def iniciar_ciclo_primera_peticion():
    thread = threading.Thread(target=ciclo_primera_peticion)
    thread.start()

def ciclo_primera_peticion():
    server_abajo = True
    while server_abajo:
        try:
            peticion = requests.get("http://0.0.0.0:3000/")
            if peticion.status_code == 200:
                server_abajo = False
        except:
            pass

'''
    Funciones de execute
'''
def execute_informacion(peticion, peticion_proceso):
    respuesta_obtener_informacion = obtener_informacion.execute(peticion)
    peticion_proceso["informacion"] = respuesta_obtener_informacion

def execute_analisis(peticion_proceso):
    respuesta_analisis = analisis.execute(peticion_proceso["sitio"], peticion_proceso["cookie"], peticion_proceso["lista_negra"],peticion_proceso["redireccionamiento"])
    peticion_proceso["analisis"] = respuesta_analisis

# Puede que truene en fuzzing_lanzar_fuzz
def execute_fuzzing(peticion_proceso, peticion_alerta):
    fuzzing_lanzar_fuzz(peticion_proceso)
    alertas_fuzzing(peticion_proceso, peticion_alerta)
    
# Puede que truene en explotacion_lanzar_exploit
def execute_explotacion(con, peticion_proceso, peticion_alerta):
    datos_explotacion, datos_identificados = obtener_datos_consulta_exploits(peticion_proceso)
    explotacion_lanzar_exploit(con, datos_identificados, datos_explotacion, peticion_proceso)
    alertas_explotacion(peticion_proceso, peticion_alerta)
    
def execute_alerta(peticion_alerta):
    resultado = enviar_alertas(peticion_alerta)
    return resultado

def execute_reporte(peticion_proceso, peticion_reporte):
    # reporte_informacion_general(peticion_proceso, peticion_reporte)
    # reporte_puertos(peticion_proceso, peticion_reporte)
    # reporte_dns_dumpster(peticion_proceso, peticion_reporte)
    # reporte_robtex(peticion_proceso, peticion_reporte)
    # reporte_b_f_l(peticion_proceso, peticion_reporte)
    # reporte_cifrados(peticion_proceso, peticion_reporte)
    # reporte_plugins(peticion_proceso, peticion_reporte)
    # reporte_archivos(peticion_proceso, peticion_reporte)
    # reporte_cve(peticion_proceso, peticion_reporte)
    # reporte_headers(peticion_proceso, peticion_reporte)
    reporte_vulnerabilidades(peticion_proceso, peticion_reporte)
    reporte_vulnerabilidades_por_pagina(peticion_proceso, peticion_reporte)
    reporte_posibles_vulnerabilidades(peticion_proceso, peticion_reporte)
    # reporte_explotacion(peticion_proceso, peticion_reporte)

    reportes.execute(peticion_reporte)
    sitio = peticion_reporte["sitio"].replace(",","_").replace("/","_").replace(":","_")
    fecha = peticion_reporte["fecha"].replace(",","_").replace(" ","_").replace("/","_").replace(":","_")
    ruta_previa = "{0}_{1}".format(sitio,fecha)
    try:
        mkdir(ruta_previa)
    except FileExistsError:
        pass
    reportes_csv_crear(peticion_reporte,ruta_previa)
    reportes_json_crear(peticion_proceso,ruta_previa)
'''
    Funciones de lanzamiento
'''
def fuzzing_lanzar_fuzz(peticion_proceso):
    for posicion_pagina in range(len(peticion_proceso["analisis"]["paginas"])):
        json_fuzzing = {
            "url":peticion_proceso["analisis"]["paginas"][posicion_pagina]["pagina"],
            "cookie":peticion_proceso["cookie"]
        }
        print(json_fuzzing["url"])
        forms = fuzzing.execute(json_fuzzing)
        if forms != False:
            peticion_proceso["analisis"]["paginas"][posicion_pagina].update(forms)

def explotacion_lanzar_exploit(con, datos_identificados, datos_explotacion, peticion_proceso):
    exploits = buscar_exploits(datos_identificados, con)
    if len(exploits) != 0:
        exploits = list({(e["ruta"],e["lenguaje"]):e for e in exploits}.values())
        explotaciones = explotacion.execute(datos_explotacion,exploits)
        peticion_proceso.update(explotaciones)
    else:
        peticion_proceso.update({"explotaciones":{}})

'''
    Funciones de obtener y enviar alertas
'''
def enviar_alertas(peticion_alerta):
    alertas.execute(peticion_alerta)

def alertas_fuzzing(peticion_proceso, peticion_alerta):
    for posicion_pagina in range(len(peticion_proceso["analisis"]["paginas"])):
        fuzzing_alertas_vulnerables, fuzzing_alertas_posibles_vulnerables = fuzzing_obtener_alertas_vulnerables(peticion_proceso["analisis"]["paginas"][posicion_pagina])
        if "motivo" in fuzzing_alertas_vulnerables:
            peticion_alerta["paginas"].append(fuzzing_alertas_vulnerables)    
        else:
            peticion_alerta["paginas"].append({"pagina":"","motivo":"Fuzzing","estado":"Sin vulnerabilidades"})
        
        if "motivo" in fuzzing_alertas_posibles_vulnerables:
            peticion_alerta["paginas"].append(fuzzing_alertas_posibles_vulnerables)    
        else:
            peticion_alerta["paginas"].append({"pagina":"","motivo":"Fuzzing","estado":"Sin posibles vulnerabilidades"})

def alertas_explotacion(peticion_proceso, peticion_alerta):
    explotacion_alertas = explotacion_obtener_alertas(peticion_proceso)
    if len(explotacion_alertas) != 0:
        peticion_alerta["paginas"].append(explotacion_alertas)
    else:
        peticion_alerta["paginas"].append({"pagina":"","motivo":"Explotación","estado":"Sin posibles vulnerabilidades"})

'''
    Funciones de estructuras de las alertas
'''

def fuzzing_obtener_alertas_vulnerables(forms):
    forms_alertas_vulnerabilidades = {}
    forms_alertas_vulnerabilidades["pagina"] = forms["pagina"]
    forms_alertas_posibles_vulnerabilidades = {}
    forms_alertas_posibles_vulnerabilidades["pagina"] = forms["pagina"]
    motivo_vulnerabilidad = ""
    motivo_posible_vulnerabilidad = ""
    posible = 0
    posible_lfi = 0
    for tipo_form in forms:
        if tipo_form == "forms":
            for form_unico in forms[tipo_form]:
                xss = 0
                sqli = 0
                sqli_blind = 0
                sqli_blind_time = 0
                
                for datos_form in forms[tipo_form][form_unico]:
                    if datos_form["xss"] == True:
                        xss += 1
                    
                    if datos_form["sqli"] == True:
                        sqli += 1
                    
                    if datos_form["sqli_blind"] == True:
                        sqli_blind += 1
                    
                    if datos_form["sqli_blind_time"] == True:
                        sqli_blind_time += 1
                    
                    if datos_form["posible_vulnerabilidad_comun"] == True:
                        posible += 1

                if xss != 0:
                    motivo_vulnerabilidad += "Form \"{0}\": {1} vulnerabilidades XSS\n".format(form_unico, xss)
                if sqli != 0:
                    motivo_vulnerabilidad += "Form \"{0}\": {1} vulnerabilidades SQLi\n".format(form_unico, sqli)
                if sqli_blind != 0:
                    motivo_vulnerabilidad += "Form \"{0}\": {1} vulnerabilidades SQLi Blind\n".format(form_unico, sqli_blind)
                if sqli_blind_time != 0:
                    motivo_vulnerabilidad += "Form \"{0}\": {1} vulnerabilidades SQLi Blind Time\n".format(form_unico, sqli_blind_time)

        elif tipo_form == "vulnerabilidades":
            for vulnerabilidad in forms[tipo_form]:
                lfi = 0

                for datos_vulnerabilidades in forms[tipo_form][vulnerabilidad]:
                    if datos_vulnerabilidades["lfi"] == True:
                        lfi += 1

                    if datos_vulnerabilidades["posible_vulnerabilidad"] == True:
                        posible_lfi += 1

                if lfi != 0:
                    motivo_vulnerabilidad += "{0} vulnerabilidades LFI\n".format(lfi)

    if posible != 0:
        motivo_posible_vulnerabilidad += "{0} posibles vulnerabilidades SQLi\n".format(posible)

    if posible_lfi != 0:
        motivo_posible_vulnerabilidad += "{0} posibles vulnerabilidades LFI\n".format(posible_lfi)

    if motivo_posible_vulnerabilidad != "":
        forms_alertas_posibles_vulnerabilidades["motivo"] = motivo_posible_vulnerabilidad
        forms_alertas_posibles_vulnerabilidades["estado"] = "Posibles vulnerables"

    if motivo_vulnerabilidad != "":
        forms_alertas_vulnerabilidades["motivo"] = motivo_vulnerabilidad
        forms_alertas_vulnerabilidades["estado"] = "Vulnerable"
    
    
    return forms_alertas_vulnerabilidades, forms_alertas_posibles_vulnerabilidades


def explotacion_obtener_alertas(explotaciones):
    explotacion_alertas = {}
    explotacion_alertas["pagina"] = "sitio " + explotaciones["sitio"]
    motivo = ""
    for exploit in explotaciones["explotaciones"]:
        for puerto in explotaciones["explotaciones"][exploit]:
            if explotaciones["explotaciones"][exploit][puerto] == 1:
                motivo += "Exploit {0} ejecutado con Éxito\n".format(exploit)
                break
    if motivo != "":
        explotacion_alertas["motivo"] = motivo
        explotacion_alertas["estado"] = "Vulnerable"
        return explotacion_alertas
    return {}

'''
    Funciones de reportes
'''

def validar_campo(peticion, valor):
    if valor in peticion:
        return peticion[valor]
    return "NA"

def obtener_cifrados_debiles(peticion_proceso):
    cifrados = 0
    if len(peticion_proceso["analisis"]["cifrados"]) != 0:
        for cifrado in peticion_proceso["analisis"]["cifrados"]:
            if cifrado == "debil":
                cifrados += 1
    return cifrados

def obtener_vulnerabilidades(peticion_proceso):
    vulnerabilidades = 0
    posibles_vulnerabilidades = 0
    for pagina in peticion_proceso["analisis"]["paginas"]:
        for tipo in pagina:
            if tipo == "forms":
                for form in pagina[tipo]:
                    for resultados in pagina[tipo][form]:
                        for ataque in ["xss","sqli","sqli_blind","sqli_blind_time","posible_vulnerabilidad_comun"]:
                            resultado_ataque = resultados[ataque]
                            if resultado_ataque == True:
                                if ataque == "xss":
                                    vulnerabilidades += 1
                                elif ataque == "sqli":
                                    vulnerabilidades += 1
                                elif ataque == "sqli_blind":
                                    vulnerabilidades += 1
                                elif ataque == "sqli_blind_time":
                                    vulnerabilidades += 1
                                elif ataque == "posible_vulnerabilidad_comun":
                                    posibles_vulnerabilidades += 1

            elif tipo == "vulnerabilidades":
                for vulnerabilidad in pagina[tipo]:
                    for resultado in pagina[tipo][vulnerabilidad]:
                        if resultado["lfi"] == True:
                            vulnerabilidades += 1
                        elif resultado["posible_vulnerabilidad"]:
                            posibles_vulnerabilidades += 1
    return vulnerabilidades, posibles_vulnerabilidades

def obtener_explotaciones(peticion_proceso):
    explotacion = 0
    for exploit in peticion_proceso["explotaciones"]:
        for puerto in peticion_proceso["explotaciones"][exploit]:
            if peticion_proceso["explotaciones"][exploit][puerto] == 1:
                explotacion += 1
                break
    return explotacion

def obtener_pais(peticion_proceso):
    pais = peticion_proceso["informacion"]["robtex"]["informacion"]["pais"]
    pais_secundario = peticion_proceso["informacion"]["dnsdumpster"]["host"][0]["pais"]
    if pais == "NA" and pais_secundario != "":
        pais = pais_secundario
    return pais

def obtener_puertos_grafica(peticion_reporte):
    puertos_generales = []
    puertos_generales.append(len(peticion_reporte["informacion"]["puertos"]["abiertos"]))
    puertos_generales.append(len(peticion_reporte["informacion"]["puertos"]["cerrados"]))
    puertos_generales.append(len(peticion_reporte["informacion"]["puertos"]["filtrados"]))
    return puertos_generales

def obtener_cifrados_grafica(peticion_proceso):
    resultados_grafica = [0,0,0]
    if len(peticion_proceso["analisis"]["cifrados"]) != 0:
        for dato in peticion_proceso["analisis"]["cifrados"]:
            if peticion_proceso["analisis"]["cifrados"][dato] == "debil":
                resultados_grafica[0] += 1
            if peticion_proceso["analisis"]["cifrados"][dato] == "recomendado":
                resultados_grafica[1] += 1
            if peticion_proceso["analisis"]["cifrados"][dato] == "seguro":
                resultados_grafica[2] += 1
        return resultados_grafica
    return [0,0,0]

def crear_grafica_puertos(grafica, reporte_relativo):
    abiertos = grafica[0]
    cerrados = grafica[1]
    filtrados = grafica[2]
    puertos_estado = ["Abiertos","Cerrados","Filtrados"]
    puertos = [abiertos,cerrados,filtrados]

    colors = ['#024C81', '#E7A44C', '#538A6B']
    informacion_diagrama = go.Figure(data=[go.Pie(labels=puertos_estado, values=puertos)])
    informacion_diagrama.update_traces(hoverinfo='label+percent', textinfo='value', textfont_size=20,
                  marker=dict(colors=colors, line=dict(color='#000000', width=1)))
    informacion_diagrama.update_layout(title_text="Resultados del módulo de información")
    informacion_diagrama.write_html(reporte_relativo, full_html=False, include_plotlyjs="cdn")

def crear_puertos(puertos_individuales, reporte_relativo):
    analisis = {
                "categoria":"",
                "titulo":"Puertos",
                "grafica":reporte_relativo,
                "cabecera":["Tipo","Puerto","Protocolo","Servicio"],
                "datos":puertos_individuales,
    }
    return analisis

def crear_informacion_general(datos_generales):
    analisis = {
                "categoria":"",
                "titulo":"Información general",
                "grafica":"",
                "cabecera":["Nombre","Descripción"],
                "datos":datos_generales,
    }
    return analisis

def crear_dnsdumpster(dnsdumpster):
    analisis = {
        "categoria":"",
        "titulo":"DNS Dumpster",
        "grafica":"",
        "cabecera":["Tipo","Valor","IP", "DNS Inverso", "País"],
        "datos":dnsdumpster
    }
    return analisis

def crear_robtex(robtex):
    analisis = {
                "categoria":"",
                "titulo":"Robtex",
                "grafica":"",
                "cabecera":["Tipo","Dominio","Sominio - IP"],
                "datos":robtex
    }
    return analisis

def crear_b_f_l(bfl):
    analisis = {
                "categoria":"",
                "titulo":"Bibliotecas, Frameworks, Lenguajes",
                "grafica":"",
                "cabecera":["Tipo","Nombre", "Versión"],
                "datos":bfl
    }
    return analisis

def crear_plugins(plugins):
    analisis = {
                "categoria":"",
                "titulo":"Plugins",
                "grafica":"",
                "cabecera":["Nombre"],
                "datos":plugins
    }
    return analisis

def crear_archivos(archivos):
    analisis = {
                "categoria":"",
                "titulo":"Archivos",
                "grafica":"",
                "cabecera":["Nombre"],
                "datos":archivos
    }
    return analisis

def crear_cve(cve):
    analisis = {
                "categoria":"",
                "titulo":"CVE",
                "grafica":"",
                "cabecera":["Nombre"],
                "datos":cve
    }
    return analisis

def crear_headers(headers):
    analisis = {
                "categoria":"",
                "titulo":"Headers",
                "grafica":"",
                "cabecera":["Nombre"],
                "datos":headers
    }
    return analisis
 
def crear_grafica_cifrados(grafica, reporte_relativo):
    debil = grafica[0]
    recomendado = grafica[1]
    seguro = grafica[2]
    puertos_estado = ["Debil","Recomendado","Seguro"]
    puertos = [debil,recomendado,seguro]

    colors = ['#024C81', '#E7A44C', '#538A6B']
    analasis_diagrama = go.Figure(data=[go.Pie(labels=puertos_estado, values=puertos)])
    analasis_diagrama.update_traces(hoverinfo='label+percent', textinfo='value', textfont_size=20,
                  marker=dict(colors=colors, line=dict(color='#000000', width=1)))
    analasis_diagrama.update_layout(title_text="Resultados del módulo de análisis")
    analasis_diagrama.write_html(reporte_relativo, full_html=False, include_plotlyjs="cdn")

def crear_cifrados(cifrados, reporte_relativo):
    analisis = {
                "categoria":"",
                "titulo":"Cifrados",
                "grafica":reporte_relativo,
                "cabecera":["Nombre","Interpretación"],
                "datos":cifrados
    }
    return analisis

def crear_grafica_vulnerabilidades(grafica, reporte):
    xss = grafica[0]
    sqli = grafica[1]
    sqli_blind = grafica[2]
    sqli_blind_time = grafica[3]
    lfi = grafica[4]
    upload = grafica[5]

    ataques = ["XSS","SQLi","SQLi Blind","SQLi Blind Time","LFI", "Upload"]
    ataques_valores = [xss,sqli,sqli_blind,sqli_blind_time,lfi,upload]

    colors = ['#233D53', '#064B73', '#F9F3E6', "#737574", "FA532E","fab62e"]
    fuzzing_diagrama = go.Figure(data=[go.Pie(labels=ataques, values=ataques_valores)])
    fuzzing_diagrama.update_traces(hoverinfo='label+percent', textinfo='value', textfont_size=20,
                  marker=dict(colors=colors, line=dict(color='#000000', width=1)))
    fuzzing_diagrama.update_layout(title_text="Resultados del módulo de fuzzing")
    fuzzing_diagrama.write_html(reporte, full_html=False, include_plotlyjs="cdn")

def crear_vulnerabilidades(vulnerabilidades, reporte_relativo):
    analisis = {
                "categoria":"",
                "titulo":"Vulnerabilidades",
                "grafica":reporte_relativo,
                "cabecera":["XSS","SQLi","SQLi Blind","SQLi Blind Time","LFI","Upload"],
                "datos":vulnerabilidades
    }
    return analisis

def crear_vulnerabilidades_pagina(vulnerabilidades):
    analisis = {
                "categoria":"",
                "titulo":"Vulnerabilidades por página",
                "grafica":"",
                "cabecera":["Página","XSS","SQLi","SQLi Blind","SQLi Blind Time","LFI","Upload"],
                "datos":vulnerabilidades
    }
    return analisis

def crear_posibles_vulnerabilidades(vulnerabilidades):
    analisis = {
                "categoria":"",
                "titulo":"Posibles Vulnerabilidades",
                "grafica":"",
                "cabecera":["SQLi", "LFI","Upload"],
                "datos":vulnerabilidades
    }
    return analisis

def crear_grafica_explotacion(grafica, reporte):
    exito = grafica[0]
    fracaso = grafica[2]
    inconcluso = grafica[1]
    ataques = ["Exito","Fracaso","Inconcluso"]


    ataques_resultado = [exito, fracaso, inconcluso]
    colors = ['#024C81', '#E7A44C', '#538A6B']
    explotacion_diagrama = go.Figure(data=[go.Pie(labels=ataques, values=ataques_resultado)])
    explotacion_diagrama.update_traces(hoverinfo='label+percent', textinfo='value', textfont_size=20,
                  marker=dict(colors=colors, line=dict(color='#000000', width=1)))
    explotacion_diagrama.update_layout(title_text="Resultados del módulo de Explotación")
    explotacion_diagrama.write_html(reporte, full_html=False, include_plotlyjs="cdn")

def crear_explotacion(explotacion, reporte_relativo):
    analisis = {
                "categoria":"",
                "titulo":"Explotación",
                "grafica":reporte_relativo,
                "cabecera":["Nombre", "Resultado"],
                "datos":explotacion
    }
    return analisis

##

def reporte_informacion_general(peticion_proceso, peticion_reporte):
    datos_generales = []
    sitio = peticion_proceso["sitio"]
    ip = peticion_proceso["informacion"]["robtex"]["informacion"]["ip"]
    pais = obtener_pais(peticion_proceso)
    servidor = validar_campo(peticion_proceso["analisis"]["servidor"], "nombre")
    cms = validar_campo(peticion_proceso["analisis"]["cms"], "nombre")
    puertos = len(peticion_proceso["informacion"]["puertos"]["abiertos"])
    cifrados = obtener_cifrados_debiles(peticion_proceso)
    cve = len(peticion_proceso["analisis"]["vulnerabilidades"])
    vulnerabilidad, posibles_vulnerabilidades = obtener_vulnerabilidades(peticion_proceso)
    explotacion = obtener_explotaciones(peticion_proceso)
    datos_generales.append(["Sitio",sitio])
    datos_generales.append(["IP",ip])
    datos_generales.append(["País",pais])
    datos_generales.append(["Servidor",servidor])
    datos_generales.append(["CMS",cms])
    datos_generales.append(["CVE",cve])
    datos_generales.append(["Explotación",explotacion])
    datos_generales.append(["Vulnerabilidades",vulnerabilidad])
    datos_generales.append(["Posibles Vulnerabilidades",posibles_vulnerabilidades])
    datos_generales.append(["Cifrados",cifrados])
    datos_generales.append(["Puertos",puertos])
    
    analisis = crear_informacion_general(datos_generales)
    peticion_reporte["analisis"].append(analisis)

def reporte_puertos(peticion_proceso, peticion_reporte):
    puertos_individuales = []
    reporte = root + "/templates/ifram_grafica_informacion.html"
    reporte_relativo = "/reporte-informacion"

    for dato in peticion_proceso["informacion"]["puertos"]:
        for valor in peticion_proceso["informacion"]["puertos"][dato]:
            puerto = valor["puerto"]
            protocolo = valor["protocolo"]
            servicio = valor["servicio"]
            puertos_individuales.append([ dato.capitalize()[:-1], puerto, protocolo, servicio.capitalize() ])

    if len(puertos_individuales) == 0:
        puertos_individuales.append(["NA","NA","NA","NA"])

    grafica = obtener_puertos_grafica(peticion_proceso)
    crear_grafica_puertos(grafica, reporte)
    analisis = crear_puertos(puertos_individuales, reporte_relativo)
    peticion_reporte["analisis"].append(analisis)

def reporte_dns_dumpster(peticion_proceso, peticion_reporte):
    dnsdumpster = []

    for tipo in peticion_proceso["informacion"]["dnsdumpster"]:
        for arreglo in peticion_proceso["informacion"]["dnsdumpster"][tipo]:
            if tipo == "txt":
                dnsdumpster.append([ tipo.capitalize(), arreglo, "NA","NA","NA"])

            else:
                dominio = arreglo["dominio"]
                ip = arreglo["ip"]
                dns_inverso = arreglo["dns_inverso"]
                pais = arreglo["pais"]
                if tipo == "host" and dominio != "" and ip != "" and dns_inverso != "" and pais != "":
                    dnsdumpster.append([ tipo.capitalize(), dominio, ip, dns_inverso, pais ])

    if len(dnsdumpster) == 0:
        dnsdumpster.append(["NA","NA","NA","NA","NA"])

    analisis = crear_dnsdumpster(dnsdumpster)
    peticion_reporte["analisis"].append(analisis)

def reporte_robtex(peticion_proceso, peticion_reporte):
    robtex = []
    for dato in peticion_proceso["informacion"]["robtex"]:
        if dato == "informacion":
            continue

        if len(peticion_proceso["informacion"]["robtex"][dato]) == 0:
            continue

        for tipo in peticion_proceso["informacion"]["robtex"][dato]:
            dominio = tipo["dominio"]
            if "dns" in tipo:
                subdominio = tipo["dns"]

            elif "host" in tipo:
                subdominio = tipo["host"]

            else:
                subdominio = "NA"

            robtex.append([ dato.capitalize(), dominio, subdominio ])

    if len(robtex) == 0:
        robtex.append(["NA","NA","NA"])
        
    analisis = crear_robtex(robtex)
    peticion_reporte["analisis"].append(analisis)

def reporte_b_f_l(peticion_proceso, peticion_reporte):
    bfl = []

    for tipo in peticion_proceso["analisis"]:
        if tipo == "librerias" or tipo == "lenguajes" or tipo == "frameworks":
            for dato in peticion_proceso["analisis"][tipo]:
                nombre = dato["nombre"]
                if "version" in dato:
                    if len(dato["version"]) == 0:
                        bfl.append([tipo.capitalize()[:-1],nombre,"NA"])
                    else:
                        for version in dato["version"]:
                            bfl.append([tipo.capitalize()[:-1],nombre,version])

    if len(bfl) == 0:
        bfl = [["No se encontraron {0}".format("datos"), "NA"]]

    analisis = crear_b_f_l(bfl)
    peticion_reporte["analisis"].append(analisis)

def reporte_cifrados(peticion_proceso, peticion_reporte):
    cifrados = []
    reporte = root + "/templates/ifram_grafica_analisis.html"
    reporte_relativo = "/reporte-analisis"

    if len(peticion_proceso["analisis"]["cifrados"]) != 0:
        for dato in peticion_proceso["analisis"]["cifrados"]:
            cifrados.append([dato.replace("_"," "), peticion_proceso["analisis"]["cifrados"][dato].capitalize()])
    
    if len(cifrados) == 0:
        cifrados = [["No se encontraron cifrados","NA"]]
    
    grafica = obtener_cifrados_grafica(peticion_proceso)
    crear_grafica_cifrados(grafica, reporte)
    analisis = crear_cifrados(cifrados,reporte_relativo)
    peticion_reporte["analisis"].append(analisis)

def reporte_plugins(peticion_proceso, peticion_reporte):
    plugins = []
    if len(peticion_proceso["analisis"]["plugins"]) != 0:
        for dato in peticion_proceso["analisis"]["plugins"]:
            plugins.append([dato])
    else: 
        plugins = [["No se encontraron {0}".format("plugins")]]

    analisis = crear_plugins(plugins)
    peticion_reporte["analisis"].append(analisis)

def reporte_archivos(peticion_proceso, peticion_reporte):
    archivos = []
    if len(peticion_proceso["analisis"]["archivos"]) != 0:
        for dato in peticion_proceso["analisis"]["archivos"]:
            archivos.append([dato])
    else: 
        archivos = [["No se encontraron {0}".format("archivos")]]

    analisis = crear_archivos(archivos)
    peticion_reporte["analisis"].append(analisis)

def reporte_cve(peticion_proceso, peticion_reporte):
    vulnerabilidades = []
    if len(peticion_proceso["analisis"]["vulnerabilidades"]) != 0:
        for dato in peticion_proceso["analisis"]["vulnerabilidades"]:
            vulnerabilidades.append([dato])
    else: 
        vulnerabilidades = [["No se encontraron {0}".format("vulnerabilidades")]]

    analisis = crear_cve(vulnerabilidades)
    peticion_reporte["analisis"].append(analisis)

def reporte_headers(peticion_proceso, peticion_reporte):
    headers = []
    if len(peticion_proceso["analisis"]["headers"]) != 0:
        for dato in peticion_proceso["analisis"]["headers"]:
            headers.append([dato])
    else: 
        headers = [["No se encontraron {0}".format("headers")]]

    analisis = crear_headers(headers)
    peticion_reporte["analisis"].append(analisis)

def reporte_vulnerabilidades(peticion_proceso, peticion_reporte):
    reporte = root + "/templates/ifram_grafica_fuzzing.html"
    reporte_relativo = "/reporte-fuzzing"
    vulnerabilidades = [[0,0,0,0,0,0]]
    grafica = [0,0,0,0,0,0]
    for pagina in peticion_proceso["analisis"]["paginas"]:
        for tipo in pagina:
            if tipo == "forms":
                for form in pagina[tipo]:
                    for resultados in pagina[tipo][form]:
                        for ataque in ["xss","sqli","sqli_blind","sqli_blind_time"]:
                            resultado_ataque = resultados[ataque]
                            if resultado_ataque == True:
                                if ataque == "xss":
                                    vulnerabilidades[0][0] += 1
                                elif ataque == "sqli":
                                    vulnerabilidades[0][1] += 1
                                elif ataque == "sqli_blind":
                                    vulnerabilidades[0][2] += 1
                                elif ataque == "sqli_blind_time":
                                    vulnerabilidades[0][3] += 1

            elif tipo == "vulnerabilidades":
                for tipo_vulnerabilidad in pagina[tipo]:
                    for vulnerabilidad in pagina[tipo][tipo_vulnerabilidad]:
                        if vulnerabilidad["lfi"] == True:
                            vulnerabilidades[0][4] += 1

            elif tipo == "forms_upload":
                for form in pagina[tipo]:
                    for vulnerabilidad in pagina[tipo][form]:
                        if vulnerabilidad["upload"] == True:
                            vulnerabilidades[0][5] += 1

            elif tipo == "forms_selenium":
                for form in pagina[tipo]:
                    for vulnerabilidad in pagina[tipo][form]:
                        if vulnerabilidad["xss"] == True:
                            vulnerabilidades[0][1] += 1

    grafica[0] = vulnerabilidades[0][0]
    grafica[1] = vulnerabilidades[0][1]
    grafica[2] = vulnerabilidades[0][2]
    grafica[3] = vulnerabilidades[0][3]
    grafica[4] = vulnerabilidades[0][4]
    grafica[5] = vulnerabilidades[0][5]

    crear_grafica_vulnerabilidades(grafica, reporte)
    analisis = crear_vulnerabilidades(vulnerabilidades, reporte_relativo)
    peticion_reporte["analisis"].append(analisis)

def reporte_vulnerabilidades_por_pagina(peticion_proceso, peticion_reporte):
    vulnerabilidades = []
    
    for pagina in peticion_proceso["analisis"]["paginas"]:
        vulnerabilidades_tmp = ["",0,0,0,0,0,0]
        vulnerabilidades_tmp[0] = pagina["pagina"]
        for tipo in pagina:
            if tipo == "forms":
                for form in pagina[tipo]:
                    for resultados in pagina[tipo][form]:
                        for ataque in ["xss","sqli","sqli_blind","sqli_blind_time"]:
                            resultado_ataque = resultados[ataque]
                            if resultado_ataque == True:
                                if ataque == "xss":
                                    vulnerabilidades_tmp[1] += 1
                                elif ataque == "sqli":
                                    vulnerabilidades_tmp[2] += 1
                                elif ataque == "sqli_blind":
                                    vulnerabilidades_tmp[3] += 1
                                elif ataque == "sqli_blind_time":
                                    vulnerabilidades_tmp[4] += 1

            elif tipo == "vulnerabilidades":
                for tipo_vulnerabilidad in pagina[tipo]:
                    for vulnerabilidad in pagina[tipo][tipo_vulnerabilidad]:
                        if vulnerabilidad["lfi"] == True:
                            vulnerabilidades_tmp[5] += 1

            elif tipo == "forms_upload":
                for form in pagina[tipo]:
                    for vulnerabilidad in pagina[tipo][form]:
                        if vulnerabilidad["upload"] == True:
                            vulnerabilidades_tmp[6] += 1
            
            elif tipo == "forms_selenium":
                for form in pagina[tipo]:
                    for vulnerabilidad in pagina[tipo][form]:
                        if vulnerabilidad["xss"] == True:
                            vulnerabilidades_tmp[1] += 1

        vulnerabilidades.append(vulnerabilidades_tmp.copy())

    analisis = crear_vulnerabilidades_pagina(vulnerabilidades)
    peticion_reporte["analisis"].append(analisis)
    
def reporte_posibles_vulnerabilidades(peticion_proceso, peticion_reporte):
    vulnerabilidades = [[0,0,0]]
    for pagina in peticion_proceso["analisis"]["paginas"]:
        for tipo in pagina:
            if tipo == "forms":
                for form in pagina[tipo]:
                    for resultados in pagina[tipo][form]:
                        for ataque in ["posible_vulnerabilidad_comun"]:
                            resultado_ataque = resultados[ataque]
                            if resultado_ataque == True:
                                if ataque == "posible_vulnerabilidad_comun":
                                    vulnerabilidades[0][0] += 1

            elif tipo == "vulnerabilidades":
                for tipo_vulnerabilidad in pagina[tipo]:
                    for vulnerabilidad in pagina[tipo][tipo_vulnerabilidad]:
                        if vulnerabilidad["posible_vulnerabilidad"] == True:
                            vulnerabilidades[0][1] += 1
            
            elif tipo == "forms_upload":
                for form in pagina[tipo]:
                    for vulnerabilidad in pagina[tipo][form]:
                        if vulnerabilidad["posible_vulnerabilidad_comun"] == True:
                            vulnerabilidades[0][2] += 1

            elif tipo == "forms_selenium":
                for form in pagina[tipo]:
                    for vulnerabilidad in pagina[tipo][form]:
                        if vulnerabilidad["posible_vulnerabilidad_comun"] == True:
                            vulnerabilidades[0][1] += 1

    analisis = crear_posibles_vulnerabilidades(vulnerabilidades)
    peticion_reporte["analisis"].append(analisis)

def reporte_explotacion(peticion_proceso, peticion_reporte):
    reporte = root + "/templates/ifram_grafica_explotacion.html"
    reporte_relativo = "/reporte-explotacion"

    explotacion = []
    grafica = [0,0,0]
    for exploit in peticion_proceso["explotaciones"]:
        explotacion_temporal = ["",""]
        explotacion_temporal[0] = exploit
        for puerto in peticion_proceso["explotaciones"][exploit]:
            if peticion_proceso["explotaciones"][exploit][puerto] == 1:
                explotacion_temporal[1] = "Exitoso"
                break

            if peticion_proceso["explotaciones"][exploit][puerto] == 0:
                explotacion_temporal[1] = "Inconcluso"

            if peticion_proceso["explotaciones"][exploit][puerto] == -1:
                explotacion_temporal[1] = "Fracaso"

        if explotacion_temporal[1] == "Exitoso":
            grafica[0] += 1
            
        if explotacion_temporal[1] == "Inconcluso":
            grafica[1] += 1

        if explotacion_temporal[1] == "Fracaso":
            grafica[2] += 1

        explotacion.append(explotacion_temporal.copy())
    crear_grafica_explotacion(grafica, reporte)
    analisis = crear_explotacion(explotacion, reporte_relativo)
    peticion_reporte["analisis"].append(analisis)

'''
    Funciones de utilidades para las funciones de execute
'''

# Explotación
## Identificar los exploits válidos por Software, CMS o CVE
def buscar_exploits(datos_identificados, con):
    exploits = []
    for software in datos_identificados["software"]:
        json_software = {
            "software_nombre":software["software_nombre"].strip(),
            "software_version":software["software_version"]
        }
        exploit_software = con.exploit_buscar_software(json_software,datos_identificados["profundidad"])
        for exploit in exploit_software["exploits"]:
            exploits.append(exploit)
    
    for cms in datos_identificados["cms"]:
        json_cms = {
            "cms_nombre":cms["cms_nombre"].strip(),
            "cms_categoria":cms["cms_categoria"].strip(),
            "cms_extension_nombre":cms["cms_extension_nombre"].strip(),
            "cms_extension_version":cms["cms_extension_version"]
        }
        exploit_cms = con.exploit_buscar_cms(json_cms,datos_identificados["profundidad"])
        for exploit in exploit_cms["exploits"]:
            exploits.append(exploit)

    for cve in datos_identificados["cve"]:
        exploit_cve = con.exploit_buscar_cve(cve.strip())
        for exploit in exploit_cve["exploits"]:
            exploits.append(exploit)
    return exploits

## Obtener los datos clave para buscar exploits
def obtener_datos_consulta_exploits(peticion_proceso):
    datos_identificados = {"software":[],"cms":[], "cve":[], "profundidad": 2}
    
    # Obtener Softwares
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

    datos_identificados["software"].extend(obtener_software_version_unica_puertos(peticion_proceso["informacion"]))
    # Obtener Características de CMS
    datos_identificados["cms"].extend(obtener_cms_sin_version(peticion_proceso["analisis"], "plugins", cms_nombre))

    # Obtener CVE
    if "vulnerabilidades" in peticion_proceso["analisis"]:
        for cve in peticion_proceso["analisis"]["vulnerabilidades"]:
            datos_identificados["cve"].append(cve)

    datos_identificados["profundidad"] = peticion_proceso["profundidad"]

    # Obtener datos para cargar los exploits
    if peticion_proceso["sitio"].startswith("https"):
        datos_explotacion = {"sitio":peticion_proceso["sitio"],"puertos":["443"]}
    else:
        datos_explotacion = {"sitio":peticion_proceso["sitio"],"puertos":["80"]}

    if "informacion" in peticion_proceso:
        for puerto in peticion_proceso["informacion"]["puertos"]["abiertos"]:
            if puerto != "80" or puerto != "443":
                datos_explotacion["puertos"].append(puerto["puerto"])
    return datos_explotacion, datos_identificados

## Obtener las versiones de los softwares con múltiples versiones, ej: Bibliotecas, Frameworks
def obtener_sofware_versiones(peticion_proceso, caracteristica):
    datos_identificados = []
    if caracteristica in peticion_proceso:
        for dato in peticion_proceso[caracteristica]:
            nombre = ""
            version = 0
            if "nombre" in dato:
                nombre = dato["nombre"]
            if "version" in dato:
                if len(dato["version"]) > 0:
                    for tipo in dato["version"]:
                        version = dato["version"][tipo]
                        version_regex = re.search(patron_version, version)
                        if version_regex is not None :
                            version = float(version_regex.group())
                        else:
                            version = 0
                        datos_identificados.append({"software_nombre":nombre,"software_version":version})
                if len(dato["version"]) == 0:
                    datos_identificados.append({"software_nombre":nombre,"software_version":0})
    return datos_identificados

## Obtener las versiones de los softwares con versión única, ej: Servidor, CMS
def obtener_software_version_unica(peticion_proceso, caracteristica):
    datos_identificados = []
    nombre = ""
    version = 0
    if caracteristica in peticion_proceso:
        if "nombre" in peticion_proceso[caracteristica]:
            nombre = peticion_proceso[caracteristica]["nombre"]
        if "version" in peticion_proceso[caracteristica]:
            version = peticion_proceso[caracteristica]["version"]
            version_regex = re.search(patron_version, version)
            if version_regex is not None :
                version = float(version_regex.group())
            else:
                version = 0
        datos_identificados.append({"software_nombre":nombre,"software_version":version})
    return datos_identificados

## Obtener las versiones únicas de los Plugins, Temas
def obtener_cms_sin_version(peticion_proceso, caracteristica, cms):
    datos_identificados = []
    nombre = ""
    if caracteristica in peticion_proceso:
        for dato in peticion_proceso[caracteristica]:
            nombre = dato
            datos_identificados.append({"cms_nombre":cms,"cms_categoria":caracteristica, "cms_extension_nombre":nombre,"cms_extension_version":0})
    return datos_identificados

## Obtener las versiones únicas de los Plugins, Temas
def obtener_cms_version_unica(peticion_proceso, caracteristica, cms):
    datos_identificados = []
    if caracteristica in peticion_proceso:
        for dato in peticion_proceso[caracteristica]:
            nombre = ""
            version = 0
            if "nombre" in dato:
                nombre = dato["nombre"]
            if "version" in dato:
                version = dato["version"]
                version_regex = re.search(patron_version, version)
                if version_regex is not None :
                    version = float(version_regex.group())
                else:
                    version = 0    
            datos_identificados.append({"cms_nombre":cms,"cms_categoria":caracteristica, "cms_extension_nombre":nombre,"cms_extension_version":version})
    return datos_identificados

## Obtener las versiones de los softwares con versión única, ej: HTTP
def obtener_software_version_unica_puertos(peticion_proceso):
    datos_identificados = []
    version = 0

    for puertos in peticion_proceso["puertos"]["abiertos"]:
        puerto = str(puertos["servicio"])
        if "version" in puertos:
            version = str(puertos["version"])
            version_regex = re.search(patron_version, version)
            if version_regex:
                version = float(version_regex.group())
            else:
                version = 0
        datos_identificados.append({"software_nombre":puerto,"software_version":version})
    return datos_identificados

# Reportes
## Crear archivo CSV
def reportes_csv_crear(peticion_reporte, ruta_previa):
    ruta = "{0}/cvs".format(ruta_previa)
    try:
        mkdir(ruta)
    except FileExistsError:
        pass
    for cvs in peticion_reporte["analisis"]:
        categoria = cvs["categoria"].replace(" ","_")
        titulo = cvs["titulo"].replace(" ","_").replace(",","_")
        if titulo == "":
            titulo = cvs["cabecera"][0].replace(" ","_")
        titulo = titulo.strip()
        if titulo == "Interés":
            titulo = "Plugins"
        if titulo in ["Archivos","Headers","Plugins","Librerías__Frameworks__Lenguajes","Vulnerabilidades"]:
            categoria = "Analisis"
        if titulo in ["Robtex","Cifrados","DNS_Dumpster","Google"]:
            categoria = "Informacion"
        if titulo in ["Resultados_individuales"]:
            categoria = "Fuzzing"
        valores_cabecera = ""
        archivo_particular = "{0}/{1}_{2}.cvs".format(ruta,categoria,titulo)

        for cabecera in cvs["cabecera"]:
            valores_cabecera += cabecera + ","
        valores_cabecera = valores_cabecera[:-1]

        with open(archivo_particular,"w") as archivo_cvs:
            archivo_cvs.write(valores_cabecera + "\n")
            for datos in cvs["datos"]:
                valores_datos = ""
                for dato in datos:
                    valores_datos += str(dato).replace(",","_") + ","
                valores_datos = valores_datos[:-1]
                archivo_cvs.write(valores_datos + "\n")

def reportes_json_crear(peticion, ruta_previa):
    ruta = "{0}/json".format(ruta_previa)
    try:
        mkdir(ruta)
    except FileExistsError:
        pass
    archivo = "{0}/analisis.json".format(ruta)
    with open(archivo, "w") as reporte_archivo:
        reporte_archivo.write(json.dumps(peticion))

'''
    Rutas
'''
# Función principal
@app.route("/")
def principal():
    return render_template("app.html")

@app.route("/reporte")
def reporte():
    return render_template("reporte.html")

@app.route("/reporte-informacion")
def reporte_grafica_informacion():
    return render_template("ifram_grafica_informacion.html")

@app.route("/reporte-analisis")
def reporte_grafica_analisis():
    return render_template("ifram_grafica_analisis.html")

@app.route("/reporte-fuzzing")
def reporte_grafica_fuzzing():
    return render_template("ifram_grafica_fuzzing.html")

@app.route("/reporte-explotacion")
def reporte_grafica_explotacion():
    return render_template("ifram_grafica_explotacion.html")

@app.route("/proximos-escaneos", methods=["GET","POST"])
def proximos_escaneos():
    if request.method == "POST":
        respuesta = proximos_peticion_escaneos()
        return respuesta

# Función para iniciar el análisis
@app.route("/ejecucion", methods=["GET","POST"])
def ejecucion():
    if request.method == "POST":
        peticion_json = request.json
        if peticion_json["fecha"] == "":
            respuesta = cola.add_peticion(peticion_json)
            #respuesta = ejecucion_analisis(peticion_json)
        return respuesta
    if request.method == "GET":
        return "GET no"

# Función para consultar todos los reportes
@app.route("/consulta-volcado", methods=["GET","POST"])
def consulta_volcado():
    if request.method == "POST":
        respuesta = consulta_peticion_volcado()
        return respuesta

# Función para consultar un reporte
@app.route("/consulta-reporte", methods=["GET","POST"])
def consulta_reporte():
    if request.method == "POST":
        peticion_json = request.get_json()
        #validar_json_consulta(peticion_json)
        respuesta = consulta_peticion_reporte(peticion_json)
        return respuesta

# Función para crear exploit
@app.route("/exploits-crear", methods=["GET","POST"])
def exploits():
    if request.method == "POST":
        peticion_json = request.get_json()
        respuesta = exploits_peticion_crear(peticion_json)
        return respuesta
    if request.method == "GET":
        return "GET no"

# Función para consultar todos los exploits
@app.route("/exploits-volcado", methods=["GET","POST"])
def exploits_volcado():
    if request.method == "POST":
        respuesta = exploits_peticion_volcado()
        return respuesta
    if request.method == "GET":
        return "GET no"

# función para editar un exploit
@app.route("/exploits-editar", methods=["GET","POST"])
def exploits_editar():
    if request.method == "POST":
        peticion_json = request.get_json()
        respuesta = exploits_peticion_editar(peticion_json)
        return respuesta
    if request.method == "GET":
        return "GET no"

# Función para actualizar un exploit
@app.route("/exploits-actualizar", methods=["GET","POST"])
def exploits_actualizar():
    if request.method == "POST":
        peticion_json = request.get_json()
        respuesta = exploits_peticion_actualizar(peticion_json)
        return respuesta
    if request.method == "GET":
        return "GET no"

# Función para eliminar un exploit
@app.route("/exploits-eliminar", methods=["GET","POST"])
def exploits_eliminar():
    if request.method == "POST":
        peticion_json = request.get_json()
        respuesta = exploits_peticion_eliminar(peticion_json)
        return respuesta
    if request.method == "GET":
        return "GET no"

# Función de prueba
@app.route("/prueba", methods=["GET","POST"])
def prueba():
    if request.method == "POST":
        sleep(15)
        return "respuesta"
    if request.method == "GET":
        return "GET no"

# Variable de encolamiento
cola = Encolamiento()


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
# Ejecucion de Flask
if __name__ == "__main__":
    iniciar_ciclo_primera_peticion()
    app.run(host='0.0.0.0', port=3000, debug=True)