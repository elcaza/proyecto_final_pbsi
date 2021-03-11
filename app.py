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
from os import path, remove
import plotly.express as px
from datetime import datetime
import plotly.graph_objects as go
import json
from time import sleep
import requests
import threading

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
    Expresiones regulares
'''
# Detectar la versión
patron_version = r"^(\d+\.?\d*)"

'''
    Modo de ejecucion:
        
        Ejecucion -> Obtener_informacion -> Análisis [Ejecucion de Fuzzing[Hilos] -> Lista de vulnerabilidades y Lista de posibles vulnerabilidades]
            -> Identificacion -> Explotacion [-> Lista de vulnerabilidades, Lista de posibles vulnerabilidades y Lista de Fracasos]
                -> Reporte

        Base de exploits
        Consulta
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
            "lista_negra":peticion["lista_negra"]
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

        
        print("Iniciando Información")
        execute_informacion(peticion, peticion_proceso, peticion_reporte)

        print("Iniciando Análisis")
        execute_analisis(peticion_proceso, peticion_reporte)

        print("Iniciando Fuzzing")
        #peticion_proceso["analisis"]["paginas"] = [{"pagina":"http://www.altoromutual.com:8080/status_check.jsp","forms":{}}]
        execute_fuzzing(peticion_proceso, peticion_alerta, peticion_reporte)

        print("Iniciando Explotacion")
        execute_explotacion(con, peticion_proceso, peticion_alerta, peticion_reporte)

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
    0
    if analisis is not None:
        peticion_reporte = {
            "sitio":analisis["sitio"],
            "fecha":analisis["fecha"],
            "analisis":[],
        }

        reporte_informacion(analisis, peticion_reporte)
        reporte_analisis(analisis, peticion_reporte)
        reporte_fuzzing(analisis, peticion_reporte)
        reporte_explotacion(analisis, peticion_reporte)
        execute_reporte(peticion_reporte)
        return json.dumps({"estado":"ok"})
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
    peticiones = cola.get_peticiones()
    pendientes = []
    if len(peticiones) != 0:
        peticion_actual = cola.get_peticion_actual()
        pendientes.append({"sitio":peticion_actual["sitio"],"fecha":peticion_actual["fecha"],"estado":"Actual"})
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
            try:
                ejecucion_analisis(peticion)
            except Exception as e:
                print("Ocurrió un error bro", e)
            #ejecucion_analisis(peticion)
        cola.reset_peticion_actual()
        sleep(2)

def iniciar_ciclo_primera_peticion():
    thread = threading.Thread(target=ciclo_primera_peticion)
    thread.start()

def ciclo_primera_peticion():
    server_abajo = True
    while server_abajo:
        try:
            peticion = requests.get("http://127.0.0.1:3000/")
            if peticion.status_code == 200:
                server_abajo = False
        except:
            pass

'''
    Funciones de execute
'''
def execute_informacion(peticion, peticion_proceso, peticion_reporte):
    respuesta_obtener_informacion = obtener_informacion.execute(peticion)
    peticion_proceso["informacion"] = respuesta_obtener_informacion
    reporte_informacion(peticion_proceso, peticion_reporte)

def execute_analisis(peticion_proceso, peticion_reporte):
    respuesta_analisis = analisis.execute(peticion_proceso["sitio"])
    peticion_proceso["analisis"] = respuesta_analisis
    reporte_analisis(peticion_proceso, peticion_reporte)
    

# Puede que truene en fuzzing_lanzar_fuzz
def execute_fuzzing(peticion_proceso, peticion_alerta, peticion_reporte):
    fuzzing_lanzar_fuzz(peticion_proceso)
    alertas_fuzzing(peticion_proceso, peticion_alerta)
    reporte_fuzzing(peticion_proceso, peticion_reporte)
    
# Puede que truene en explotacion_lanzar_exploit
def execute_explotacion(con, peticion_proceso, peticion_alerta, peticion_reporte):
    datos_explotacion, datos_identificados = obtener_datos_consulta_exploits(peticion_proceso)
    explotacion_lanzar_exploit(con, datos_identificados, datos_explotacion, peticion_proceso)
    alertas_explotacion(peticion_proceso, peticion_alerta)
    reporte_explotacion(peticion_proceso, peticion_reporte)
    
def execute_alerta(peticion_alerta):
    resultado = enviar_alertas(peticion_alerta)
    return resultado

def execute_reporte(peticion_reporte):
    reportes.execute(peticion_reporte)
    
'''
    Funciones de lanzamiento
'''
def fuzzing_lanzar_fuzz(peticion_proceso):
    for posicion_pagina in range(len(peticion_proceso["analisis"]["paginas"])):
        json_fuzzing = {
            "url":peticion_proceso["analisis"]["paginas"][posicion_pagina]["pagina"],
            "hilos":4,
            "cookie":peticion_proceso["cookie"]
        }
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
        fuzzing_alertas = fuzzing_obtener_alertas(peticion_proceso["analisis"]["paginas"][posicion_pagina])
        if len(fuzzing_alertas) != 0:
            peticion_alerta["paginas"].append(fuzzing_alertas)    
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

def fuzzing_obtener_alertas(forms):
    forms_alertas = {}
    forms_alertas["pagina"] = forms["pagina"]
    motivo = ""
    for form in forms["forms"]:
        vulnerable = 0
        xss = 0
        sqli = 0
        lfi = 0
        for pagina in forms["forms"][form]:
            if pagina["xss"] == True:
                xss += 1
                vulnerable = 1
            if pagina["sqli"] == True:
                sqli += 1
                vulnerable = 1
            if pagina["lfi"] == True:
                lfi += 1
                vulnerable = 1
        if vulnerable == 1:
            motivo += '''
            Form: {0}
            {1} XSS Vulnerables
            {2} SQLi Posiblemente Vulnerables
            {3} LFI Vulnerables
            '''.format(form, xss, sqli, lfi)
        vulnerable = 0
    if motivo != "":
        forms_alertas["motivo"] = motivo
        forms_alertas["estado"] = "Posiblemente vulnerable"
        return forms_alertas
    return {}

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
def reporte_informacion(peticion_proceso, peticion_reporte):
    informacion = {}
    informacion["datos"] = informacion_obtener_datos(peticion_proceso)
    informacion["dns_dumpster"] = informacion_obtener_dnsdumpster(peticion_proceso["informacion"]["dnsdumpster"])
    informacion["robtex"] = informacion_obtener_robtex(peticion_proceso["informacion"]["robtex"])
    informacion["puertos_generales"] = informacion_obtener_puertos_generales(peticion_proceso["informacion"]["puertos"])
    informacion["puertos_individuales"] = informacion_obtener_puertos_individuales(peticion_proceso["informacion"]["puertos"])
    reportes_informacion_crear(informacion, peticion_reporte)
    

def reporte_analisis(peticion_proceso, peticion_reporte):
    analisis = {}
    analisis["servidor"] = analisis_obtener_servidor(peticion_proceso["analisis"]["servidor"], "Servidor") # Nombre y versión
    analisis["cms"] = analisis_obtener_servidor(peticion_proceso["analisis"]["cms"], "CMS") # Nombre y versión
    analisis["librerias"] = analisis_obtener_cms_datos(peticion_proceso["analisis"]["librerias"],"Libreria") #  Nombre y versión
    analisis["frameworks"] = analisis_obtener_cms_datos(peticion_proceso["analisis"]["frameworks"],"Framework") # Nombre y versión
    analisis["lenguajes"] = analisis_obtener_cms_datos(peticion_proceso["analisis"]["lenguajes"],"Lenguaje") # Nombre y versión
    
    analisis["cifrados"], grafica_cifrados = analisis_obtener_cifrados(peticion_proceso["analisis"]["cifrados"]) # Nombre y tipo

    analisis["plugins"] = analisis_obtener_datos(peticion_proceso["analisis"]["plugins"],"Plugins") # Listado
    analisis["archivos"] = analisis_obtener_datos(peticion_proceso["analisis"]["archivos"], "Archivos") # Listado
    analisis["vulnerabilidades"] = analisis_obtener_datos(peticion_proceso["analisis"]["vulnerabilidades"], "Vulnerabilidades conocidas") # Listado
    analisis["headers"] = analisis_obtener_datos(peticion_proceso["analisis"]["headers"],"Headers") # Listado

    analisis["paginas"] = analisis_obtener_paginas(peticion_proceso["analisis"]["paginas"]) # Total

    reportes_analisis_crear(analisis, grafica_cifrados, peticion_reporte)
    

def reporte_fuzzing(peticion_proceso, peticion_reporte):
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
    #print(fuzzing_estadistica_general)
    reportes_fuzzing_crear(fuzzing_estadistica_general, fuzzing_estadistica_individual, peticion_reporte)
        
    

def reporte_explotacion(peticion_proceso, peticion_reporte):
    explotacion_estadisticas = estadisticas_explotacion(peticion_proceso)
    #explotacion_estadisticas = [["AAAA.SH","Exitoso"], ["BBBB.SH","Fracaso"], ["CCCC.SH","Inconcluso"]]
    reportes_explotacion_crear(explotacion_estadisticas, peticion_reporte)
    

'''
    Funciones para crear la estructura de los reportes
'''
def reportes_informacion_crear(informacion, peticion_reporte):
    reporte = root + "/templates/ifram_grafica_informacion.html"
    reporte_relativo = "/reporte-informacion"

    analisis = reportes_informacion_crear_general(informacion["datos"])
    peticion_reporte["analisis"].append(analisis)

    reportes_informacion_crear_general_puertos_grafica(informacion["puertos_generales"],reporte)
    analisis = reportes_informacion_crear_general_puertos(informacion["puertos_generales"],reporte_relativo)
    peticion_reporte["analisis"].append(analisis)
    
    analisis = reportes_informacion_crear_subgeneral(informacion)
    for valor in analisis:
        peticion_reporte["analisis"].append(valor)

def reportes_analisis_crear(datos_analisis, grafica_cifrados, peticion_reporte):
    reporte = root + "/templates/ifram_grafica_analisis.html"
    reporte_relativo = "/reporte-analisis"

    reportes_analisis_crear_cifrados_grafica(grafica_cifrados,reporte)
    analisis = reportes_analisis_crear_general(datos_analisis, reporte_relativo)
    for valor in analisis:
        peticion_reporte["analisis"].append(valor)

def reportes_fuzzing_crear(fuzzing_estadistica_general, fuzzing_estadistica_individual, peticion_reporte):
    reporte = root + "/templates/ifram_grafica_fuzzing.html"
    reporte_relativo = "/reporte-fuzzing"

    reportes_fuzzing_crear_general_grafica(fuzzing_estadistica_general, reporte )
    analisis = reportes_fuzzing_crear_general(fuzzing_estadistica_general, reporte_relativo )
    peticion_reporte["analisis"].append(analisis)
    
    analisis = reportes_fuzzing_crear_individual(fuzzing_estadistica_individual)
    peticion_reporte["analisis"].append(analisis)


def reportes_explotacion_crear(explotacion_estadisticas, peticion_reporte):
    reporte = root + "/templates/ifram_grafica_explotacion.html"
    reporte_relativo = "/reporte-explotacion"

    reportes_explotacion_crear_general_grafica(explotacion_estadisticas,reporte)
    analisis = reportes_explotacion_crear_general(explotacion_estadisticas, reporte_relativo)
    peticion_reporte["analisis"].append(analisis)
    

'''
    Funciones para obtener los datos para los reportes
'''
# Información
def informacion_obtener_datos(peticion_proceso):
    sitio = peticion_proceso["sitio"]
    ip = peticion_proceso["informacion"]["robtex"]["informacion"]["ip"]
    pais = peticion_proceso["informacion"]["robtex"]["informacion"]["pais"]
    pais_secundario = peticion_proceso["informacion"]["dnsdumpster"]["host"][0]["pais"]
    servidor = peticion_proceso["informacion"]["dnsdumpster"]["host"][0]["cabecera"]
    
    if pais == "NA" and pais_secundario != "":
        pais = pais_secundario
    if servidor == "":
        servidor = "NA"
    
    return [["Sitio",sitio],["IP",ip],["Pais",pais],["Servidor",servidor]]

def informacion_obtener_dnsdumpster(datos):
    dnsdumpster = []
    for dato in datos:
        for tipo in datos[dato]:
            dominio = tipo["dominio"]
            ip = tipo["ip"]
            dns_inverso = tipo["dns_inverso"]
            pais = tipo["pais"]
            cabecera = tipo["cabecera"]
            if dato == "host" and dominio != "" and ip != "" and dns_inverso != "" and pais != "":
                dnsdumpster.append([ dato.capitalize(), dominio, ip, dns_inverso, pais ])
    if len(dnsdumpster) == 0:
        dnsdumpster.append(["NA","NA","NA","NA","NA"])
    return dnsdumpster

def informacion_obtener_robtex(datos):
    print(datos)
    robtex = []
    for dato in datos:
        if dato == "informacion":
            continue
        if len(datos[dato]) == 0:
            continue
        for tipo in datos[dato]:
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
    return robtex

def informacion_obtener_puertos_generales(datos):
    puertos_generales = []
    puertos_generales.append("Puertos")
    puertos_generales.append(len(datos["abiertos"]))
    puertos_generales.append(len(datos["cerrados"]))
    puertos_generales.append(len(datos["filtrados"]))
    return puertos_generales

def informacion_obtener_puertos_individuales(datos):
    puertos_individuales = []
    for dato in datos:
        for valor in datos[dato]:
            puerto = valor["puerto"]
            protocolo = valor["protocolo"]
            servicio = valor["servicio"]
            puertos_individuales.append([ dato.capitalize(), puerto, protocolo, servicio.capitalize() ])
    if len(puertos_individuales) == 0:
        puertos_individuales.append(["NA","NA","NA","NA"])
    return puertos_individuales

# Análisis
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

def analisis_obtener_cifrados(datos):
    resultados = []
    resultados_grafica = [0,0,0]
    if len(datos) != 0:
        for dato in datos:
            resultados.append([dato.replace("_"," "), datos[dato].capitalize()])
            if datos[dato] == "debil":
                resultados_grafica[0] += 1
            if datos[dato] == "recomendado":
                resultados_grafica[1] += 1
            if datos[dato] == "seguro":
                resultados_grafica[2] += 1
        return resultados, resultados_grafica
    return [["No se encontraron cifrados","NA"]], [0,0,0]

def analisis_obtener_paginas(datos): return [[len(datos)]]

# Fuzzing
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

# Explotación
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

'''
    Funciones de crear las gráficas de los reportes
'''
def reportes_informacion_crear_general_puertos_grafica(informacion, reporte):
    abiertos = informacion[1]
    cerrados = informacion[2]
    filtrados = informacion[3]
    puertos_estado = ["Abiertos","Cerrados","Filtrados"]
    puertos = [abiertos,cerrados,filtrados]

    colors = ['#024C81', '#E7A44C', '#538A6B']
    informacion_diagrama = go.Figure(data=[go.Pie(labels=puertos_estado, values=puertos)])
    informacion_diagrama.update_traces(hoverinfo='label+percent', textinfo='value', textfont_size=20,
                  marker=dict(colors=colors, line=dict(color='#000000', width=1)))
    informacion_diagrama.update_layout(title_text="Resultados del módulo de información")
    informacion_diagrama.write_html(reporte, full_html=False, include_plotlyjs="cdn")

def reportes_analisis_crear_cifrados_grafica(grafica_cifrados,reporte):
    debil = grafica_cifrados[0]
    recomendado = grafica_cifrados[1]
    seguro = grafica_cifrados[2]
    puertos_estado = ["Debil","Recomendado","Seguro"]
    puertos = [debil,recomendado,seguro]

    colors = ['#024C81', '#E7A44C', '#538A6B']
    analasis_diagrama = go.Figure(data=[go.Pie(labels=puertos_estado, values=puertos)])
    analasis_diagrama.update_traces(hoverinfo='label+percent', textinfo='value', textfont_size=20,
                  marker=dict(colors=colors, line=dict(color='#000000', width=1)))
    analasis_diagrama.update_layout(title_text="Resultados del módulo de análisis")
    analasis_diagrama.write_html(reporte, full_html=False, include_plotlyjs="cdn")

def reportes_fuzzing_crear_general_grafica(fuzzing_estadisticas,reporte):
    xss = fuzzing_estadisticas[1]
    sqli = fuzzing_estadisticas[2]
    lfi = fuzzing_estadisticas[3]
    ataques = ["XSS","SQLi","LFI"]

    colors = ['#024C81', '#E7A44C', '#538A6B']
    fuzzing_diagrama = go.Figure(data=[go.Pie(labels=ataques, values=[xss,sqli,lfi])])
    fuzzing_diagrama.update_traces(hoverinfo='label+percent', textinfo='value', textfont_size=20,
                  marker=dict(colors=colors, line=dict(color='#000000', width=1)))
    fuzzing_diagrama.update_layout(title_text="Resultados del módulo de fuzzing")
    fuzzing_diagrama.write_html(reporte, full_html=False, include_plotlyjs="cdn")

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
    colors = ['#024C81', '#9e2424', '#adadad']
    explotacion_diagrama = go.Figure(data=[go.Pie(labels=ataques, values=ataques_resultado)])
    explotacion_diagrama.update_traces(hoverinfo='label+percent', textinfo='value', textfont_size=20,
                  marker=dict(colors=colors, line=dict(color='#000000', width=1)))
    explotacion_diagrama.update_layout(title_text="Resultados del módulo de Explotación")
    explotacion_diagrama.write_html(reporte, full_html=False, include_plotlyjs="cdn")

'''
    Funciones para crear los submódulos de los reportes
'''
# Información
def reportes_informacion_crear_general(datos_host):
    analisis = {
                "categoria":"Informacion",
                "titulo":"Resultados generales",
                "grafica":"",
                "cabecera":["Nombre","Descripción"],
                "datos":datos_host,
    }
    return analisis

def reportes_informacion_crear_general_puertos(informacion, reporte):
    analisis = {
                "categoria":"Informacion",
                "titulo":"Puertos",
                "grafica":reporte,
                "cabecera":["Tipo","Abiertos","Cerrados","Filtrados"],
                "datos":[informacion],
    }
    return analisis

def reportes_informacion_crear_subgeneral(informacion):
    analisis = []
    datos = {}
    datos["puertos_individuales"] = informacion["puertos_individuales"]
    datos["dns_dumpster"] = informacion["dns_dumpster"]
    datos["robtex"] = informacion["robtex"]

    for dato in datos:
        if dato == "puertos_individuales":
            analisis_individual = {
                        "categoria":"Analisis",
                        "titulo":"Puerto individuales",
                        "grafica":"",
                        "cabecera":["Tipo","Puerto","Protocolo","Servicio"],
                        "datos":datos[dato]
            }
        elif dato == "dns_dumpster":
            analisis_individual = {
                        "categoria":"",
                        "titulo":"DNS Dumpster",
                        "grafica":"",
                        "cabecera":["Tipo","Dominio","IP", "DNS Inverso", "País"],
                        "datos":datos[dato]
            }
        elif dato == "robtex":
            analisis_individual = {
                        "categoria":"",
                        "titulo":"Robtex",
                        "grafica":"",
                        "cabecera":["Tipo","Dominio","IP"],
                        "datos":datos[dato]
            }
        analisis.append(analisis_individual)


    return analisis

# Análisis
def reportes_analisis_crear_general(datos_analisis, grafica_cifrados):
    analisis = []
    datos = {}
    datos["servidor"] = datos_analisis["servidor"] + datos_analisis["cms"]
    datos["cms"] = datos_analisis["librerias"] + datos_analisis["frameworks"] + datos_analisis["lenguajes"]
    datos["cifrados"] = datos_analisis["cifrados"]
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
        elif dato == "cifrados":
            analisis_individual = {
                        "categoria":"",
                        "titulo":"Cifrados",
                        "grafica":grafica_cifrados,
                        "cabecera":["Nombre","Interpretación"],
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

# Explotacion
def reportes_explotacion_crear_general(explotacion_estadisticas, reporte):
    analisis = {
                "categoria":"Explotacion",
                "titulo":"Resultados generales",
                "grafica":reporte,
                "cabecera":["Exploit","Resultado"],
                "datos":explotacion_estadisticas
    }
    return analisis


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
        for puerto in peticion_proceso["informacion"]["puertos"]["abiertos"]:
            if puerto != "80" or puerto != "443":
                datos_explotacion["puertos"].append(puerto["puerto"])

    return datos_explotacion, datos_identificados

## Obtener las versiones de los softwares con múltiples versiones, ej: Bibliotecas, Frameworks
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
                    version_regex = re.search(patron_version, version)
                    if version_regex is not None :
                        version = float(version_regex.group())
                    else:
                        version = 0
                    datos_identificados.append({"software_nombre":nombre,"software_version":version})
            if len(peticion_proceso[caracteristica]["version"]) == 0:
                datos_identificados.append({"software_nombre":nombre,"software_version":0})
    return datos_identificados

## Obtener las versiones de los softwares con versión única, ej: Servidor, CMS
def obtener_software_version_unica(peticion_proceso, caracteristica):
    datos_identificados = []
    nombre = ""
    version = ""
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
    print(request.method)
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
    app.run(host='127.0.0.1', port=3000, debug=True)