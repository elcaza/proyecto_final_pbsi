# Importaciones
## Flask
import base64
import re
from flask import Flask, render_template, request
from flask_cors import CORS

## Utileria
from os import path, remove, mkdir
from datetime import datetime
import plotly.graph_objects as go
import json
from time import sleep
import requests
import threading
import concurrent.futures
from base64 import b64decode
import sys

## Modulos
from modules.obtencion_informacion import obtener_informacion as obtener_informacion
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
            -> Identificacion -> Explotacion [-> Lista de vulnerabilidades, Lista de inconclusos y Lista de Fracasos]


        Base de exploits
        Consulta
        Reportes
'''

class SingletonMeta(type):
    '''
        Clase que permite crear clases de tipo Singleton
    '''
    _instances = {}
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            instance = super().__call__(*args, **kwargs)
            cls._instances[cls] = instance
        return cls._instances[cls]

class Encolamiento(metaclass=SingletonMeta):
    '''
        Clase de tipo Singleton que sirve para añadir peticiones a la cola
        esto para no saturar al sistema operativo

        .........
        Atributos
        ---------
        peticion : array
            lista de peticiones en cola
        peticion_actual : dict
            copia de la peticion en curso

        Metodos
        -------
        add_peticion(peticion):
            añade una peticion a la cola

        pop_peticion():
            remueve el primer elemento de la cola

        len_peticion():
            regresa la cantidad de peticiones en cola

        get_peticiones():
            regresa la lista de peticiones

        get_peticion_actual():
            regresa la peticion actual

        reset_peticion_actual():
            asigna a un diccionario vacio el objeto de peticion_actual
    '''
    def __init__(self):
        self.peticion = []
        self.peticion_actual = {}

    def add_peticion(self, peticion):
        self.peticion.append(peticion)
        return {"status":"Petición enviada"}

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

class Masivo():
    '''
        Clase que se encarga de realizar todo el proceso analizar un sitio

        .........

        Atributos
        ---------
        peticion : dict
            diccionario que contiene los datos para iniciar el proceso
        con : Conector
            objeto que permite la interaccion con Mongo
        utileria : Utileria
            objeto que sirve para validar los datos del peticion
        peticion_proceso : dict
            diccionario que guarda todo el analisis
        peticion_reporte : dict
            diccionario que funciona para crear los reportes
        peticion_alerta : dict
            diccionario que funciona para lanzar las alertas obtenidas
        error : str
            ruta donde se escribiran los errores
        
        Metodos
        -------
        set_error():
            Funcion que guarda el nombre del archivo de errores

        peticion_actual():
            Funcion que regresa verdadero si la peticion se ejecuta al instante
            
        validar_peticion():
            Funcion que carga las peticiones y regresa verdadero si el proceso fue exitoso
            
        ejecucion_analisis():
            Funcion principal que realiza todo el procedimiento del analisis
            
        execute_informacion():
            Funcion que ejecuta el modulo de obtener_informacion y guarda el resultado en el diccionario peticion_proceso en la llave "informacion"
            
        execute_analisis():   
            Funcion que ejecuta el modulo de analsisi y guarda el resultado en el diccionario peticion_proceso en la llave "analisis"
            
        execute_fuzzing():  
            Funcion que ejecuta el modulo de fuzzing, una vez terminado ejecuta el modulo de alertas_fuzzing para guardar las (posibles)vulnerabilidades encontradas
        
        execute_explotacion():
            Funcion que ejecuta el modulo de identificacion y de explotacion, guarda el resultado en el diccionario peticion_proceso en la llave "explotacion"
            
        fuzzing_lanzar_fuzz():
            Funcion que crea hasta un maximo de 4 hilos donde cada uno lanzara un fuzzing completo a una pagina
            el resultado sera guardado dentro de las paginas del analisis
            
        explotacion_lanzar_exploit():
            Funcion que identifica a los exploits que pueden ser utilizados para luego llamar al modulo de explotacion 
            para ejecutar cada exploit
            
        execute_alerta():
            Funcion que lanza al modulo alerta para que envia el conjunto de alertas a los destinatarios
            
        enviar_alertas():
            Funcion que lanza el modulo de las alertas
            
        alertas_fuzzing():
            Funcion que itera los resultados del fuzzing en busca de vulnerabilidades y posibles vulnerabilidades
            
        alertas_explotacion():
            Funcion que itera los resultados de la explotacion en busca de vulnerabilidades
            
        fuzzing_obtener_alertas_vulnerables(forms):
            Funcion que itera pagina en busca de los resultados exitosos
            
        explotacion_obtener_alertas(explotaciones):
            Funcion que itera las explotaciones en busca de alguna ejecucion de exploit exitosa
            
        buscar_exploits():
            Funcion que realiza una busqueda de exploits con los datos identificados
            
        obtener_datos_consulta_exploits():
            Funcion que regresa los datos identificados y datos de explotacion a partir del analisis 
            
        obtener_sofware_versiones(peticion_proceso, caracteristica):
            Funcion que se encarga de extraer el nombre del software y multiples versiones partiendo de las caracteristica
            
        obtener_software_version_unica(peticion_proceso, caracteristica):
            Funcion que se encarga de extraer el nombre del software y su version partiendo de las caracteristica
        
        obtener_cms(peticion_proceso, caracteristica, cms):
            Funcion que se encarga de extraer el nombre del cms, categoria de la extension, nombre de la extension con su respectiva version
            partiendo de las caracteristica
            
        obtener_software_version_unica_puertos(peticion_proceso):
            Funcion que se encarga de extraer el nombre del software y su version partiendo de los puertos
        
    '''
    def __init__(self, peticion):
        self.peticion = peticion
        self.con = Conector()
        self.utileria = Utileria()
        self.set_error()
        actual = self.peticion_actual()
        valido = self.validar_peticion()
        if actual and valido:
            self.ejecucion_analisis()

    def set_error(self):
        '''
            Funcion que guarda el nombre del archivo de errores
        '''
        ruta = root + "/modules/strings.json"
        with open(ruta, "r") as archivo_strings:
            self.error = root + "/errores/" + json.load(archivo_strings)["ERROR_LOG"]

    def peticion_actual(self):
        '''
            Funcion que regresa verdadero si la peticion se ejecuta al instante
        '''
        if self.peticion["fecha"] != "":
            programacion.execute(self.peticion)
            return False
        return True

    def validar_peticion(self):
        '''
            Funcion que carga las peticiones y regresa verdadero si el proceso fue exitoso
        '''
        if self.utileria.validar_json_sitio(self.peticion):
            self.peticion_proceso = {
                "sitio":self.peticion["sitio"],
                "cookie":self.peticion["cookie"],
                "fecha":datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
                "profundidad":self.peticion["profundidad"],
                "redireccionamiento":self.peticion["redireccionamiento"],
                "lista_negra":self.peticion["lista_negra"],
                "analisis":{"paginas":[]},
                "verificacion":{"informacion":0,"analisis":1,"fuzzing":0,"explotacion":0}
            }
            self.peticion_reporte = {
                "sitio":self.peticion_proceso["sitio"],
                "fecha":self.peticion_proceso["fecha"],
                "analisis":[],
            }
            self.peticion_alerta = {
                "subject":"Análisis del sitio \"{0}\" finalizado".format(self.peticion_proceso["sitio"]),
                "paginas":[],
                "fecha":datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
            }
            return True
        else:
            self.peticion_proceso = {}
            self.peticion_reporte = {}
            self.peticion_alerta = {}
            return False

    def ejecucion_analisis(self):
        '''
            Funcion principal que realiza todo el procedimiento del analisis

            primero valida que le fecha sea actual, así como que contenga datos validos para lanzar el analisis
            este analisis consiste en ejecutar los modulos de "obtener informacion", "analisis", "fuzzing" y "explotacion"
        '''
            
        print("Iniciando Información")
        self.execute_informacion()

        print("Iniciando Análisis")
        self.execute_analisis()

        print("Iniciando Fuzzing")
        #self.peticion_proceso["analisis"]["paginas"] = [{"pagina":"https://localhost/drupal7/","forms":{}}]
        # self.peticion_proceso["analisis"]["paginas"] = [{"pagina":"https://seguridad.unam.mx/","forms":{}}]
        # self.peticion_proceso["analisis"]["paginas"] = [{"pagina":"https://localhost/DVWA-master/logout.php","forms":{}}]
        # self.peticion_proceso["analisis"]["paginas"] = [
        # {'pagina': 'http://testphp.vulnweb.com/search.php?test=query'}
        # ]
        # self.peticion_proceso["analisis"]["paginas"] = [
        # {'pagina': 'http://testasp.vulnweb.com/showforum.asp?id=0'},
        # # # {'pagina': 'http://altoromutual.com:8080/feedback.jsp'},#, {'pagina': 'http://altoromutual.com:8080/login.jsp'},
        # # # #{'pagina': 'http://altoromutual.com:8080/index.jsp?content=security.htm'},{'pagina': 'http://altoromutual.com:8080/status_check.jsp'},
        # # {'pagina': 'http://altoromutual.com:8080/default.jsp?content=security.htm'}, {'pagina': 'http://altoromutual.com:8080/survey_questions.jsp'}, {'pagina': 'http://altoromutual.com:8080/index.jsp?content=security.htm'}, {'pagina': 'http://altoromutual.com:8080/status_check.jsp'}, {'pagina': 'http://altoromutual.com:8080/swagger/index.html'}, {'pagina': 'http://altoromutual.com:8080/index.jsp/swagger/index.html'},#{'pagina': 'http://altoromutual.com:8080/swagger/index.html'}
        # ]
        self.execute_fuzzing()

        print("Iniciando Explotacion")
        self.execute_explotacion()
    
        print("Enviando alertas")
        self.execute_alerta()
            
        print("Guardando analisis")
        self.con.guardar_analisis(self.peticion_proceso)

        return "Reporte generado"

    def execute_informacion(self):
        '''
            Funcion que ejecuta el modulo de obtener_informacion y guarda el resultado en el diccionario peticion_proceso en la llave "informacion"
        '''
        try:
            respuesta_obtener_informacion = obtener_informacion.execute(self.peticion)
            self.peticion_proceso["informacion"] = respuesta_obtener_informacion
            self.peticion_proceso["verificacion"]["informacion"] = 1
        except Exception as e:
            tipo, base, rastro = sys.exc_info()
            archivo = path.split(rastro.tb_frame.f_code.co_filename)[1]
            with open (self.error, "a") as error:
                error.write("{0},{1}:{2},{3}:{4},{5}:{6},{7}{8}".format("El módulo de \"Información\" falló en",e ,"tipo" ,tipo ,"archivo" ,archivo, "linea",rastro.tb_lineno,"\n"))

    def execute_analisis(self):
        '''
            Funcion que ejecuta el modulo de analsisi y guarda el resultado en el diccionario peticion_proceso en la llave "analisis"

            Parametros
            ----------
            peticion : dict
                contiene los datos de sitio, cookie, lista negra y el redireccionamiento
            peticion_proceso : dict
                diccionario que guardara el resultado del analisis
        '''
        respuesta_analisis = analisis.execute(self.peticion_proceso["sitio"], self.peticion_proceso["cookie"], self.peticion_proceso["lista_negra"],self.peticion_proceso["redireccionamiento"])
        self.peticion_proceso["analisis"] = respuesta_analisis
        self.peticion_proceso["verificacion"]["analisis"] = 1
        # try:
        #     respuesta_analisis = analisis.execute(self.peticion_proceso["sitio"], self.peticion_proceso["cookie"], self.peticion_proceso["lista_negra"],self.peticion_proceso["redireccionamiento"])
        #     self.peticion_proceso["analisis"] = respuesta_analisis
        #     self.peticion_proceso["verificacion"]["analisis"] = 1
        # except Exception as e:
        #     tipo, base, rastro = sys.exc_info()
        #     archivo = path.split(rastro.tb_frame.f_code.co_filename)[1]
        #     with open (self.error, "a") as error:
        #         error.write("{0},{1}:{2},{3}:{4},{5}:{6},{7}{8}".format("El módulo de \"Análisis\" falló en",e ,"tipo" ,tipo ,"archivo" ,archivo, "linea",rastro.tb_lineno,"\n"))

    def execute_fuzzing(self):
        '''
            Funcion que ejecuta el modulo de fuzzing, una vez terminado ejecuta el modulo de alertas_fuzzing para guardar las (posibles)vulnerabilidades encontradas
        '''
        if self.peticion_proceso["verificacion"]["analisis"] == 1:
            self.fuzzing_lanzar_fuzz()
            self.alertas_fuzzing()
            self.peticion_proceso["verificacion"]["fuzzing"] = 1
            # try:
            #     self.fuzzing_lanzar_fuzz()
            #     self.alertas_fuzzing()
            #     self.peticion_proceso["verificacion"]["fuzzing"] = 1
            # except Exception as e:
            #     tipo, base, rastro = sys.exc_info()
            #     archivo = path.split(rastro.tb_frame.f_code.co_filename)[1]
            #     with open (self.error, "a") as error:
            #         error.write("{0},{1}:{2},{3}:{4},{5}:{6},{7}{8}".format("El módulo de \"Fuzzing\" falló en",e ,"tipo" ,tipo ,"archivo" ,archivo, "linea",rastro.tb_lineno,"\n"))
        
    def execute_explotacion(self):
        '''
            Funcion que ejecuta el modulo de identificacion y de explotacion, guarda el resultado en el diccionario peticion_proceso en la llave "explotacion"
        '''
        if self.peticion_proceso["verificacion"]["analisis"] == 1 or self.peticion_proceso["verificacion"]["informacion"] == 1:
            try:
                self.datos_explotacion, self.datos_identificados = self.obtener_datos_consulta_exploits()
                self.explotacion_lanzar_exploit()
                self.alertas_explotacion()
                self.peticion_proceso["verificacion"]["explotacion"] = 1
            except Exception as e:
                tipo, base, rastro = sys.exc_info()
                archivo = path.split(rastro.tb_frame.f_code.co_filename)[1]
                with open (self.error, "a") as error:
                    error.write("{0},{1}:{2},{3}:{4},{5}:{6},{7}{8}".format("El módulo de \"Explotación\" falló en",e ,"tipo" ,tipo ,"archivo" ,archivo, "linea",rastro.tb_lineno,"\n"))

    def fuzzing_lanzar_fuzz(self):
        '''
            Funcion que crea hasta un maximo de 4 hilos donde cada uno lanzara un fuzzing completo a una pagina
            el resultado sera guardado dentro de las paginas del analisis
        '''
        futures = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            for posicion_pagina in range(len(self.peticion_proceso["analisis"]["paginas"])):
                url = self.peticion_proceso["analisis"]["paginas"][posicion_pagina]["pagina"]
                json_fuzzing = {
                    "url":url,
                    "cookie":self.peticion_proceso["cookie"]
                }
                futures.append(executor.submit(fuzzing.execute,json_fuzzing))
            for future in concurrent.futures.as_completed(futures):
                forms = future.result()
                if forms != False:
                    for posicion_pagina in range(len(self.peticion_proceso["analisis"]["paginas"])): 
                        if self.peticion_proceso["analisis"]["paginas"][posicion_pagina]["pagina"] == forms["url"]:
                            self.peticion_proceso["analisis"]["paginas"][posicion_pagina].update(forms)

    def explotacion_lanzar_exploit(self):
        '''
            Funcion que identifica a los exploits que pueden ser utilizados para luego llamar al modulo de explotacion 
            para ejecutar cada exploit
        '''
        exploits = self.buscar_exploits()
        if len(exploits) != 0:
            exploits = list({(e["ruta"],e["lenguaje"]):e for e in exploits}.values())
            explotaciones = explotacion.execute(self.datos_explotacion,exploits)
            self.peticion_proceso.update(explotaciones)
        else:
            self.peticion_proceso.update({"explotaciones":{}})

    def execute_alerta(self):
        '''
            Funcion que lanza al modulo alerta para que envia el conjunto de alertas a los destinatarios
        '''
        resultado = self.enviar_alertas()
        return resultado

    def enviar_alertas(self):
        '''
            Funcion que lanza el modulo de las alertas
        '''
        alertas.execute(self.peticion_alerta)

    def alertas_fuzzing(self):
        '''
            Funcion que itera los resultados del fuzzing en busca de vulnerabilidades y posibles vulnerabilidades
        '''
        for posicion_pagina in range(len(self.peticion_proceso["analisis"]["paginas"])):
            fuzzing_alertas_vulnerables, fuzzing_alertas_posibles_vulnerables = self.fuzzing_obtener_alertas_vulnerables(self.peticion_proceso["analisis"]["paginas"][posicion_pagina])
            if "motivo" in fuzzing_alertas_vulnerables:
                self.peticion_alerta["paginas"].append(fuzzing_alertas_vulnerables)    
                        
            if "motivo" in fuzzing_alertas_posibles_vulnerables:
                self.peticion_alerta["paginas"].append(fuzzing_alertas_posibles_vulnerables)    

    def alertas_explotacion(self):
        '''
            Funcion que itera los resultados de la explotacion en busca de vulnerabilidades
        '''
        explotacion_alertas = self.explotacion_obtener_alertas(self.peticion_proceso)
        if len(explotacion_alertas) != 0:
            self.peticion_alerta["paginas"].append(explotacion_alertas)
        else:
            self.peticion_alerta["paginas"].append({"pagina":"","motivo":"Explotación","estado":"Sin posibles vulnerabilidades"})

    def fuzzing_obtener_alertas_vulnerables(self, forms):
        '''
            Funcion que itera pagina en busca de los resultados exitosos

            Parametros
            ----------
            forms : dict
                contiene la pagina al que se realizo el fuzzing junto con sus forms
        '''
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

    def explotacion_obtener_alertas(self, explotaciones):
        '''
            Funcion que itera las explotaciones en busca de alguna ejecucion de exploit exitosa

            Parametros
            ----------
            explotaciones : dict
                contiene la pagina y el resultado de las explotaciones
        '''
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

    def obtener_datos_consulta_exploits(self):
        '''
            Funcion que regresa los datos identificados y datos de explotacion a partir del analisis 

            busca todos los software con sus versiones y las extensiones de los cms para definir los datos identificados
            para extraer los datos de explotacion usa los puertos y los sitios
        '''
        informacion = self.peticion_proceso["verificacion"]["informacion"]
        analisis = self.peticion_proceso["verificacion"]["analisis"]

        self.datos_identificados = {"software":[],"cms":[], "cve":[], "profundidad": 2}
        
        self.datos_identificados["profundidad"] = self.peticion_proceso["profundidad"]

        # Obtener datos para cargar los exploits
        if self.peticion_proceso["sitio"].startswith("https"):
            self.datos_explotacion = {"sitio":self.peticion_proceso["sitio"],"puertos":["443"],"cookie":self.peticion_proceso["cookie"]}
        else:
            self.datos_explotacion = {"sitio":self.peticion_proceso["sitio"],"puertos":["80"],"cookie":self.peticion_proceso["cookie"]}

        if informacion == 1:
            self.datos_identificados["software"].extend(self.obtener_software_version_unica_puertos(self.peticion_proceso["informacion"]))
            for puerto in self.peticion_proceso["informacion"]["puertos"]["abiertos"]:
                if puerto != "80" or puerto != "443":
                    self.datos_explotacion["puertos"].append(puerto["puerto"])

        if analisis == 1:
            self.datos_identificados["software"].extend(self.obtener_software_version_unica(self.peticion_proceso["analisis"], "servidor"))
            self.datos_identificados["software"].extend(self.obtener_sofware_versiones(self.peticion_proceso["analisis"], "lenguajes"))
            self.datos_identificados["software"].extend(self.obtener_sofware_versiones(self.peticion_proceso["analisis"], "frameworks"))
            self.datos_identificados["software"].extend(self.obtener_sofware_versiones(self.peticion_proceso["analisis"], "librerias"))
            cms = self.obtener_software_version_unica(self.peticion_proceso["analisis"], "cms")
            if len(cms) != 0:
                cms_nombre = cms[0]["software_nombre"]
                self.datos_identificados["software"].extend(cms)
                self.datos_identificados["cms"].extend(self.obtener_cms(self.peticion_proceso["analisis"], "plugins", cms_nombre))

            if "vulnerabilidades" in self.peticion_proceso["analisis"]:
                for cve in self.peticion_proceso["analisis"]["vulnerabilidades"]:
                    self.datos_identificados["cve"].append(cve)

        return self.datos_explotacion, self.datos_identificados

    def obtener_sofware_versiones(self, peticion_proceso, caracteristica):
        '''
            Funcion que se encarga de extraer el nombre del software y multiples versiones partiendo de las caracteristica

            Parametros
            ----------
            peticion_proceso : dict
                diccionario que contiene todo el analisis del sitio
            caracteristica : str
                valor para extraer el software y version del analisis
        '''
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
                            if nombre != "":
                                datos_identificados.append({"software_nombre":nombre,"software_version":version})
                    if len(dato["version"]) == 0:
                        if nombre != "":
                            datos_identificados.append({"software_nombre":nombre,"software_version":0})
        return datos_identificados

    def obtener_software_version_unica(self, peticion_proceso, caracteristica):
        '''
            Funcion que se encarga de extraer el nombre del software y su version partiendo de las caracteristica

            Parametros
            ----------
            peticion_proceso : dict
                diccionario que contiene todo el analisis del sitio
            caracteristica : str
                valor para extraer el software y version del analisis
        '''
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
            if nombre != "":
                datos_identificados.append({"software_nombre":nombre,"software_version":version})
        return datos_identificados

    def obtener_cms(self, peticion_proceso, caracteristica, cms):
        '''
            Funcion que se encarga de extraer el nombre del cms, categoria de la extension, nombre de la extension con su respectiva version
            partiendo de las caracteristica

            Parametros
            ----------
            peticion_proceso : dict
                diccionario que contiene todo el analisis del sitio
            caracteristica : str
                valor para extraer el software y version del analisis
            cms : str
                nombre del cms
        '''
        datos_identificados = []
        nombre = ""
        version = 0
        if caracteristica in peticion_proceso:
            for dato in peticion_proceso[caracteristica]:
                print(dato)
                if str(type(dato)).find("list") >= 0:
                    nombre = dato
                    datos_identificados.append({"cms_nombre":cms,"cms_categoria":caracteristica, "cms_extension_nombre":nombre,"cms_extension_version":0})

                elif str(type(dato)).find("dict") >= 0:
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

    def obtener_software_version_unica_puertos(self, peticion_proceso):
        '''
            Funcion que se encarga de extraer el nombre del software y su version partiendo de los puertos

            Parametros
            ----------
            peticion_proceso : dict
                diccionario que contiene todo el analisis del sitio
        '''
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
            if puerto != "":
                datos_identificados.append({"software_nombre":puerto,"software_version":version})
        return datos_identificados

    def buscar_exploits(self):
        '''
            Funcion que realiza una busqueda de exploits con los datos identificados
        '''
        exploits = []
        for software in self.datos_identificados["software"]:
            json_software = {
                "software_nombre":software["software_nombre"].strip(),
                "software_version":software["software_version"]
            }
            exploit_software = self.con.exploit_buscar_software(json_software,self.datos_identificados["profundidad"])
            for exploit in exploit_software["exploits"]:
                exploits.append(exploit)
        
        for cms in self.datos_identificados["cms"]:
            json_cms = {
                "cms_nombre":cms["cms_nombre"].strip(),
                "cms_categoria":cms["cms_categoria"].strip(),
                "cms_extension_nombre":cms["cms_extension_nombre"].strip(),
                "cms_extension_version":cms["cms_extension_version"]
            }
            exploit_cms = self.con.exploit_buscar_cms(json_cms,self.datos_identificados["profundidad"])
            for exploit in exploit_cms["exploits"]:
                exploits.append(exploit)

        for cve in self.datos_identificados["cve"]:
            exploit_cve = self.con.exploit_buscar_cve(cve.strip())
            for exploit in exploit_cve["exploits"]:
                exploits.append(exploit)
        return exploits

class Reportes():
    '''
        Clase que crea los reportes rescatando los datos mas importante del analisis

        .........

        Atributos
        ---------
        con : Conector
            permite la conexion con Mongo
        peticion : dict
            contiene el sitio y la fecha para buscar el analisis almacenado en Mongo
        peticion_proceso : dict
            objeto que contiene el analisis obtenido de Mongo
        peticion_reporte : dict
            objeto que permite la creacion del reporte
        ruta_previa : str
            ruta donde se guardaran los archivos CSV y JSON

        Metodos
        -------
        eliminar_reporte():
            Funcion que elimina un reporte de mongo partiendo del nombre y fecha

        consulta_peticion_reporte():
            Funcion que realiza una conexión al servidor Mongo para extraer una analisis en concreto
            
        execute_reporte():
            Funcion que extrae los datos de los modulos de obtener_informacion, analisis, fuzzing y explotacion para crear un repore en HTML
            
        reporte_informacion_general():
            Funcion que recopila la informacion general del analisis
            
        reporte_puertos():
            Funcion que recopila la informacion de puertos del analisis
            
        reporte_dns_dumpster():
            Funcion que recopila la informacion del dnsdumpster del analisis
            
        reporte_robtex():
            Funcion que recopila la informacion de robtex del analisis
            
        reporte_b_f_l():
            Funcion que recopila la informacion de bibliotecas, frameworks y lenguajes del analisis
            
        reporte_cifrados():
            Funcion que recopila la informacion de cifrados del analisis
            
        reporte_plugins():
            Funcion que recopila la informacion de plugins del analisis
            
        reporte_archivos():
            Funcion que recopila la informacion de archivos del analisis
            
        reporte_google():
            Funcion que recopila la informacion de google del analisis
            
        reporte_bing():
            Funcion que recopila la informacion de bing del analisis
            
        reporte_cve():
            Funcion que recopila la informacion de cves del analisis
            
        reporte_headers():
            Funcion que recopila la informacion de headers del analisis
            
        reporte_vulnerabilidades():
            Funcion que recopila la informacion de vulnerabilidades del analisis
            
        reporte_vulnerabilidades_por_pagina():
            Funcion que recopila la informacion de vulnerabilidades por pagina del analisis
            
        reporte_posibles_vulnerabilidades():
            Funcion que recopila la informacion de posibles vulnerabilidades del analisis
            
        reporte_explotacion():
            Funcion que recopila la informacion de explotacion del analisis
            
        validar_campo(peticion, valor):
            Funcion que valida la existencia del campo en algun diccionario
            
        obtener_cifrados_debiles(peticion_proceso):
            Funcion que regresa los cifrados debiles en el sitio
            
        obtener_vulnerabilidades(peticion_proceso):
            Funcion que regresa el total de vulnerabilidades y posibles vulnerabilidades realizadas por el fuzzing
            
        obtener_explotaciones(peticion_proceso):
            Funcion que regresa el total de explotaciones exitosas
            
        obtener_pais(peticion_proceso):
            Funcion que regresa el pais en donde se encuentra el servidor
            
        obtener_puertos_grafica(peticion_proceso):
            Funcion que regresa el total de puertos abiertos, cerrados y filtrados
            
        obtener_cifrados_grafica(peticion_proceso):
            Funcion que regresa el total de cifrados debiles, recomendados y seguros
            
        crear_informacion_general(datos_generales):
            Funcion que regresa el analisis de la informacion general para ser representada en el reporte
            
        crear_dnsdumpster(dnsdumpster):
            Funcion que regresa el analisis del dnsdumpster para ser representada en el reporte
            
        crear_robtex(robtex):
            Funcion que regresa el analisis del robtex para ser representada en el reporte
            
        crear_b_f_l(bfl):
            Funcion que regresa el analisis de las bibliotecas, lenguajes y frameworks para ser representada en el reporte
            
        crear_plugins(plugins):
            Funcion que regresa el analisis de plugins para ser representada en el reporte
            
        crear_archivos(archivos):
            Funcion que regresa el analisis de los archivos para ser representada en el reporte
            
        crear_google(enlaces):
            Funcion que regresa el analisis de google para ser representada en el reporte
            
        crear_bing(enlaces):
            Funcion que regresa el analisis de bing para ser representada en el reporte
            
        crear_cve(cve):
            Funcion que regresa el analisis de los cve para ser representada en el reporte
            
        crear_headers(headers):
            Funcion que regresa el analisis de los headers para ser representada en el reporte
            
        crear_vulnerabilidades_pagina(vulnerabilidades):
            Funcion que regresa el analisis de las vulnerabilidades por pagina para ser representada en el reporte junto con su grafica
            
        crear_posibles_vulnerabilidades(vulnerabilidades):
            Funcion que regresa el analisis de las posibles vulnerabilidades para ser representada en el reporte
            
        crear_puertos(puertos_individuales, reporte_relativo):
            Funcion que regresa el analisis de los puertos de forma individual para ser representada en el reporte
            
        crear_cifrados(cifrados, reporte_relativo):
            Funcion que regresa el analisis de los cifrados para ser representada en el reporte junto con su grafica
            
        crear_vulnerabilidades(vulnerabilidades, reporte_relativo):
            Funcion que regresa el analisis de las vulnerabilidades para ser representada en el reporte junto con su grafica
            
        crear_explotacion(explotacion, reporte_relativo):
            Funcion que regresa el analisis de las explotaciones para ser representada en el reporte junto con su grafica
            
        crear_grafica_puertos(grafica, reporte_relativo):
            Funcion que permite crear la grafica de puertos en formato HTML de tipo iframe
            
        crear_grafica_vulnerabilidades(grafica, reporte):
            Funcion que permite crear la grafica de puertos en formato HTML de tipo iframe
            
        crear_grafica_cifrados(grafica, reporte_relativo):
            Funcion que permite crear la grafica de cifrados en formato HTML de tipo iframe
            
        crear_grafica_explotacion(grafica, reporte):
            Funcion que permite crear la grafica de puertos en formato HTML de tipo iframe
            
        reportes_csv_crear():
            Funcion que crea el CSV a partir del reporte
            
        reportes_json_crear():
            Funcion que crea el JSON a partir del reporte
    '''
    def __init__(self, peticion):
        self.con = Conector()
        self.peticion = peticion
    
    def eliminar_reporte(self):
        '''
            Funcion que elimina un reporte de mongo partiendo del nombre y fecha
        '''
        self.peticion_proceso = self.con.eliminar_analisis(self.peticion)
        return json.dumps({"status":"Reporte eliminado"})

    def consulta_peticion_reporte(self):
        '''
            Funcion que realiza una conexión al servidor Mongo para extraer una analisis en concreto
        '''
        self.peticion_proceso = self.con.obtener_analisis(self.peticion)
        if self.peticion_proceso is not None:
            self.peticion_reporte = {
                "sitio":self.peticion_proceso["sitio"],
                "fecha":self.peticion_proceso["fecha"],
                "analisis":[],
            }

        self.informacion = self.peticion_proceso["verificacion"]["informacion"]
        self.analisis = self.peticion_proceso["verificacion"]["analisis"]
        self.fuzzing = self.peticion_proceso["verificacion"]["fuzzing"]
        self.explotacion = self.peticion_proceso["verificacion"]["explotacion"]

        self.execute_reporte()
        return json.dumps({"status":"Creando Reporte"})
    
    def execute_reporte(self):
        '''
            Funcion que extrae los datos de los modulos de obtener_informacion, analisis, fuzzing y explotacion para crear un repore en HTML
            realiza un dump en formato CSV y JSON el cual trae el dump completo del analisis
        '''
        self.reporte_informacion_general()
        
        if self.informacion == 1:
            self.reporte_puertos()
            self.reporte_dns_dumpster()
            self.reporte_robtex()
            self.reporte_google()
            self.reporte_bing()

        if self.analisis == 1:
            self.reporte_b_f_l()
            self.reporte_cifrados()
            self.reporte_plugins()
            self.reporte_archivos()
            self.reporte_cve()
            self.reporte_headers()

        if self.fuzzing == 1:
            self.reporte_vulnerabilidades()
            self.reporte_vulnerabilidades_por_pagina()
            self.reporte_posibles_vulnerabilidades()

        if self.explotacion == 1:
            self.reporte_explotacion()

        reportes.execute(self.peticion_reporte)
        sitio = self.peticion_reporte["sitio"].replace(",","_").replace("/","_").replace(":","_")
        fecha = self.peticion_reporte["fecha"].replace(",","_").replace(" ","_").replace("/","_").replace(":","_")
        self.ruta_previa = "{0}_{1}".format(sitio,fecha)
        try:
            mkdir(self.ruta_previa)
        except FileExistsError:
            pass
        self.reportes_csv_crear()
        self.reportes_json_crear()


    def reporte_informacion_general(self):
        '''
            Funcion que recopila la informacion general del analisis
        '''
        datos_generales = []
        sitio = self.peticion_proceso["sitio"]
        datos_generales.append(["Sitio",sitio])
        if self.informacion == 1:
            ip = self.peticion_proceso["informacion"]["robtex"]["informacion"]["ip"]
            pais = self.obtener_pais(self.peticion_proceso)
            puertos = len(self.peticion_proceso["informacion"]["puertos"]["abiertos"])
            datos_generales.append(["IP",ip])
            datos_generales.append(["País",pais])
            datos_generales.append(["Puertos",puertos])

        if self.analisis == 1:
            servidor = self.validar_campo(self.peticion_proceso["analisis"]["servidor"], "nombre")
            cms = self.validar_campo(self.peticion_proceso["analisis"]["cms"], "nombre")
            cifrados = self.obtener_cifrados_debiles(self.peticion_proceso)
            cve = len(self.peticion_proceso["analisis"]["vulnerabilidades"])

            if self.peticion_proceso["analisis"]["ioc_anomalo"]["existe"]:
                ioc_anomalo = len(self.peticion_proceso["analisis"]["ioc_anomalo"]["valores"])
            else:
                ioc_anomalo = 0

            if self.peticion_proceso["analisis"]["ioc_webshell"]["existe"]:
                ioc_webshell = len(self.peticion_proceso["analisis"]["ioc_webshell"]["valores"])
            else:
                ioc_webshell = 0

            if self.peticion_proceso["analisis"]["ioc_ejecutables"]["existe"]:
                ioc_ejecutable = len(self.peticion_proceso["analisis"]["ioc_ejecutables"]["valores"])
            else:
                ioc_ejecutable = 0

            if self.peticion_proceso["analisis"]["ioc_cryptominer"]["existe"]:
                ioc_cripto = len(self.peticion_proceso["analisis"]["ioc_cryptominer"]["valores"])
            else:
                ioc_cripto = 0

            ioc = ioc_anomalo + ioc_webshell + ioc_ejecutable + ioc_cripto
            datos_generales.append(["Servidor",servidor])
            datos_generales.append(["CMS",cms])
            datos_generales.append(["CVE",cve])
            datos_generales.append(["IOC",ioc])
            datos_generales.append(["Cifrados Débiles",cifrados])

        if self.fuzzing == 1:
            vulnerabilidad, posibles_vulnerabilidades = self.obtener_vulnerabilidades(self.peticion_proceso)
            datos_generales.append(["Vulnerabilidades",vulnerabilidad])
            datos_generales.append(["Posibles Vulnerabilidades",posibles_vulnerabilidades])

        if self.explotacion == 1:
            explotacion = self.obtener_explotaciones(self.peticion_proceso)
            datos_generales.append(["Explotación",explotacion])
        
        analisis = self.crear_informacion_general(datos_generales)
        self.peticion_reporte["analisis"].append(analisis)

    def reporte_puertos(self):
        '''
            Funcion que recopila la informacion de puertos del analisis

            Parametros
            ----------
            peticion_proceso : dict
                diccionario que contiene todo el analisis del sitio
            peticion_reporte : dict
                diccionario que sirve para crear el reporte HTML, CSV y JSON
        '''
        puertos_individuales = []
        reporte = root + "/templates/ifram_grafica_informacion.html"
        reporte_relativo = "/reporte-informacion"

        for dato in self.peticion_proceso["informacion"]["puertos"]:
            for valor in self.peticion_proceso["informacion"]["puertos"][dato]:
                puerto = valor["puerto"]
                protocolo = valor["protocolo"]
                servicio = valor["servicio"]
                puertos_individuales.append([ dato.capitalize()[:-1], puerto, protocolo, servicio.capitalize() ])

        if len(puertos_individuales) == 0:
            puertos_individuales.append(["NA","NA","NA","NA"])

        grafica = self.obtener_puertos_grafica(self.peticion_proceso)
        self.crear_grafica_puertos(grafica, reporte)
        analisis = self.crear_puertos(puertos_individuales, reporte_relativo)
        self.peticion_reporte["analisis"].append(analisis)

    def reporte_dns_dumpster(self):
        '''
            Funcion que recopila la informacion del dnsdumpster del analisis

            Parametros
            ----------
            peticion_proceso : dict
                diccionario que contiene todo el analisis del sitio
            peticion_reporte : dict
                diccionario que sirve para crear el reporte HTML, CSV y JSON
        '''
        dnsdumpster = []

        for tipo in self.peticion_proceso["informacion"]["dnsdumpster"]:
            for arreglo in self.peticion_proceso["informacion"]["dnsdumpster"][tipo]:
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

        analisis = self.crear_dnsdumpster(dnsdumpster)
        self.peticion_reporte["analisis"].append(analisis)

    def reporte_robtex(self):
        '''
            Funcion que recopila la informacion de robtex del analisis

            Parametros
            ----------
            peticion_proceso : dict
                diccionario que contiene todo el analisis del sitio
            peticion_reporte : dict
                diccionario que sirve para crear el reporte HTML, CSV y JSON
        '''
        robtex = []
        for dato in self.peticion_proceso["informacion"]["robtex"]:
            if dato == "informacion":
                continue

            if len(self.peticion_proceso["informacion"]["robtex"][dato]) == 0:
                continue

            for tipo in self.peticion_proceso["informacion"]["robtex"][dato]:
                dominio = tipo["dominio"]
                if "dns" in tipo:
                    subdominio = tipo["dns"]

                elif "host" in tipo:
                    subdominio = tipo["host"]

                else:
                    subdominio = "NA"

                robtex.append([ dato.capitalize().replace("_"," "), dominio, subdominio ])

        if len(robtex) == 0:
            robtex.append(["NA","NA","NA"])
            
        analisis = self.crear_robtex(robtex)
        self.peticion_reporte["analisis"].append(analisis)

    def reporte_b_f_l(self):
        '''
            Funcion que recopila la informacion de bibliotecas, frameworks y lenguajes del analisis

            Parametros
            ----------
            peticion_proceso : dict
                diccionario que contiene todo el analisis del sitio
            peticion_reporte : dict
                diccionario que sirve para crear el reporte HTML, CSV y JSON
        '''
        bfl = []

        for tipo in self.peticion_proceso["analisis"]:
            if tipo == "librerias" or tipo == "lenguajes" or tipo == "frameworks":
                for dato in self.peticion_proceso["analisis"][tipo]:
                    nombre = dato["nombre"]
                    if "version" in dato:
                        if len(dato["version"]) == 0:
                            bfl.append([tipo.capitalize()[:-1],nombre,"NA"])
                        else:
                            for version in dato["version"]:
                                bfl.append([tipo.capitalize()[:-1],nombre,version])

        if len(bfl) == 0:
            bfl = [["No se encontraron {0}".format("datos"), "NA"]]

        analisis = self.crear_b_f_l(bfl)
        self.peticion_reporte["analisis"].append(analisis)

    def reporte_cifrados(self):
        '''
            Funcion que recopila la informacion de cifrados del analisis

            Parametros
            ----------
            peticion_proceso : dict
                diccionario que contiene todo el analisis del sitio
            peticion_reporte : dict
                diccionario que sirve para crear el reporte HTML, CSV y JSON
        '''
        cifrados = []
        reporte = root + "/templates/ifram_grafica_analisis.html"
        reporte_relativo = "/reporte-analisis"

        if len(self.peticion_proceso["analisis"]["cifrados"]) != 0:
            for dato in self.peticion_proceso["analisis"]["cifrados"]:
                cifrados.append([dato.replace("_"," "), self.peticion_proceso["analisis"]["cifrados"][dato].capitalize()])
        
        if len(cifrados) == 0:
            cifrados = [["No se encontraron cifrados","NA"]]
        
        grafica = self.obtener_cifrados_grafica(self.peticion_proceso)
        self.crear_grafica_cifrados(grafica, reporte)
        analisis = self.crear_cifrados(cifrados,reporte_relativo)
        self.peticion_reporte["analisis"].append(analisis)

    def reporte_plugins(self):
        '''
            Funcion que recopila la informacion de plugins del analisis

            Parametros
            ----------
            peticion_proceso : dict
                diccionario que contiene todo el analisis del sitio
            peticion_reporte : dict
                diccionario que sirve para crear el reporte HTML, CSV y JSON
        '''
        plugins = []
        if len(self.peticion_proceso["analisis"]["plugins"]) != 0:
            for dato in self.peticion_proceso["analisis"]["plugins"]:
                plugins.append([dato])
        else: 
            plugins = [["No se encontraron {0}".format("plugins")]]

        analisis = self.crear_plugins(plugins)
        self.peticion_reporte["analisis"].append(analisis)

    def reporte_archivos(self):
        '''
            Funcion que recopila la informacion de archivos del analisis

            Parametros
            ----------
            peticion_proceso : dict
                diccionario que contiene todo el analisis del sitio
            peticion_reporte : dict
                diccionario que sirve para crear el reporte HTML, CSV y JSON
        '''
        archivos = []
        if len(self.peticion_proceso["analisis"]["archivos"]) != 0:
            for dato in self.peticion_proceso["analisis"]["archivos"]:
                archivos.append([dato])
        else: 
            archivos = [["No se encontraron {0}".format("archivos")]]

        analisis = self.crear_archivos(archivos)
        self.peticion_reporte["analisis"].append(analisis)

    def reporte_google(self):
        '''
            Funcion que recopila la informacion de google del analisis

            Parametros
            ----------
            peticion_proceso : dict
                diccionario que contiene todo el analisis del sitio
            peticion_reporte : dict
                diccionario que sirve para crear el reporte HTML, CSV y JSON
        '''
        enlaces = []
        if len(self.peticion_proceso["informacion"]["google"]) != 0:
            for tipo in self.peticion_proceso["informacion"]["google"]:
                for dato in self.peticion_proceso["informacion"]["google"][tipo]:
                    enlaces.append([tipo.replace("_"," ").capitalize(), dato])
        else: 
            enlaces = [["NA", "No se encontraron {0}".format("enlaces")]]

        if len(enlaces) == 0:
            enlaces = [["NA", "No se encontraron {0}".format("enlaces")]]

        analisis = self.crear_google(enlaces)
        self.peticion_reporte["analisis"].append(analisis)

    def reporte_bing(self):
        '''
            Funcion que recopila la informacion de bing del analisis

            Parametros
            ----------
            peticion_proceso : dict
                diccionario que contiene todo el analisis del sitio
            peticion_reporte : dict
                diccionario que sirve para crear el reporte HTML, CSV y JSON
        '''
        enlaces = []
        if len(self.peticion_proceso["informacion"]["bing"]) != 0:
            for tipo in self.peticion_proceso["informacion"]["bing"]:
                for dato in self.peticion_proceso["informacion"]["bing"][tipo]:
                    enlaces.append([tipo.replace("_"," ").capitalize(), dato])
        else: 
            enlaces = [["NA", "No se encontraron {0}".format("enlaces")]]

        if len(enlaces) == 0:
            enlaces = [["NA", "No se encontraron {0}".format("enlaces")]]

        analisis = self.crear_bing(enlaces)
        self.peticion_reporte["analisis"].append(analisis)

    def reporte_cve(self):
        '''
            Funcion que recopila la informacion de cves del analisis

            Parametros
            ----------
            peticion_proceso : dict
                diccionario que contiene todo el analisis del sitio
            peticion_reporte : dict
                diccionario que sirve para crear el reporte HTML, CSV y JSON
        '''
        vulnerabilidades = []
        if len(self.peticion_proceso["analisis"]["vulnerabilidades"]) != 0:
            for dato in self.peticion_proceso["analisis"]["vulnerabilidades"]:
                vulnerabilidades.append([dato])
        else: 
            vulnerabilidades = [["No se encontraron {0}".format("vulnerabilidades")]]

        analisis = self.crear_cve(vulnerabilidades)
        self.peticion_reporte["analisis"].append(analisis)

    def reporte_headers(self):
        '''
            Funcion que recopila la informacion de headers del analisis

            Parametros
            ----------
            peticion_proceso : dict
                diccionario que contiene todo el analisis del sitio
            peticion_reporte : dict
                diccionario que sirve para crear el reporte HTML, CSV y JSON
        '''
        headers = []
        if len(self.peticion_proceso["analisis"]["headers"]) != 0:
            for dato in self.peticion_proceso["analisis"]["headers"]:
                headers.append([dato])
        else: 
            headers = [["No se encontraron {0}".format("headers")]]

        analisis = self.crear_headers(headers)
        self.peticion_reporte["analisis"].append(analisis)

    def reporte_vulnerabilidades(self):
        '''
            Funcion que recopila la informacion de vulnerabilidades del analisis

            Parametros
            ----------
            peticion_proceso : dict
                diccionario que contiene todo el analisis del sitio
            peticion_reporte : dict
                diccionario que sirve para crear el reporte HTML, CSV y JSON
        '''
        reporte = root + "/templates/ifram_grafica_fuzzing.html"
        reporte_relativo = "/reporte-fuzzing"
        vulnerabilidades = [[0,0,0,0,0,0]]
        grafica = [0,0,0,0,0,0]
        for pagina in self.peticion_proceso["analisis"]["paginas"]:
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
                                vulnerabilidades[0][0] += 1

        grafica[0] = vulnerabilidades[0][0]
        grafica[1] = vulnerabilidades[0][1]
        grafica[2] = vulnerabilidades[0][2]
        grafica[3] = vulnerabilidades[0][3]
        grafica[4] = vulnerabilidades[0][4]
        grafica[5] = vulnerabilidades[0][5]

        self.crear_grafica_vulnerabilidades(grafica, reporte)
        analisis = self.crear_vulnerabilidades(vulnerabilidades, reporte_relativo)
        self.peticion_reporte["analisis"].append(analisis)

    def reporte_vulnerabilidades_por_pagina(self):
        '''
            Funcion que recopila la informacion de vulnerabilidades por pagina del analisis

            Parametros
            ----------
            peticion_proceso : dict
                diccionario que contiene todo el analisis del sitio
            peticion_reporte : dict
                diccionario que sirve para crear el reporte HTML, CSV y JSON
        '''
        vulnerabilidades = []
        
        for pagina in self.peticion_proceso["analisis"]["paginas"]:
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

        analisis = self.crear_vulnerabilidades_pagina(vulnerabilidades)
        self.peticion_reporte["analisis"].append(analisis)
        
    def reporte_posibles_vulnerabilidades(self):
        '''
            Funcion que recopila la informacion de posibles vulnerabilidades del analisis

            Parametros
            ----------
            peticion_proceso : dict
                diccionario que contiene todo el analisis del sitio
            peticion_reporte : dict
                diccionario que sirve para crear el reporte HTML, CSV y JSON
        '''
        vulnerabilidades = [[0,0,0,0]]
        for pagina in self.peticion_proceso["analisis"]["paginas"]:
            for tipo in pagina:
                if tipo == "forms":
                    for form in pagina[tipo]:
                        for resultados in pagina[tipo][form]:
                            for ataque in ["posible_vulnerabilidad_comun", "posible_vulnerabilidad_xss"]:
                                resultado_ataque = resultados[ataque]
                                if resultado_ataque == True:
                                    if ataque == "posible_vulnerabilidad_comun":
                                        vulnerabilidades[0][1] += 1
                                    if ataque == "posible_vulnerabilidad_xss":
                                        vulnerabilidades[0][0] += 1

                elif tipo == "vulnerabilidades":
                    for tipo_vulnerabilidad in pagina[tipo]:
                        for vulnerabilidad in pagina[tipo][tipo_vulnerabilidad]:
                            if vulnerabilidad["posible_vulnerabilidad"] == True:
                                vulnerabilidades[0][2] += 1
                
                elif tipo == "forms_upload":
                    for form in pagina[tipo]:
                        for vulnerabilidad in pagina[tipo][form]:
                            if vulnerabilidad["posible_vulnerabilidad_comun"] == True:
                                vulnerabilidades[0][3] += 1

                elif tipo == "forms_selenium":
                    for form in pagina[tipo]:
                        for vulnerabilidad in pagina[tipo][form]:
                            if vulnerabilidad["posible_vulnerabilidad_comun"] == True:
                                vulnerabilidades[0][1] += 1

        analisis = self.crear_posibles_vulnerabilidades(vulnerabilidades)
        self.peticion_reporte["analisis"].append(analisis)

    def reporte_explotacion(self):
        '''
            Funcion que recopila la informacion de explotacion del analisis

            Parametros
            ----------
            peticion_proceso : dict
                diccionario que contiene todo el analisis del sitio
            peticion_reporte : dict
                diccionario que sirve para crear el reporte HTML, CSV y JSON
        '''
        reporte = root + "/templates/ifram_grafica_explotacion.html"
        reporte_relativo = "/reporte-explotacion"

        explotacion = []
        grafica = [0,0,0]
        for exploit in self.peticion_proceso["explotaciones"]:
            explotacion_temporal = ["",""]
            explotacion_temporal[0] = exploit
            for puerto in self.peticion_proceso["explotaciones"][exploit]:
                if self.peticion_proceso["explotaciones"][exploit][puerto] == 1:
                    explotacion_temporal[1] = "Exitoso"
                    break

                if self.peticion_proceso["explotaciones"][exploit][puerto] == 0:
                    explotacion_temporal[1] = "Inconcluso"

                if self.peticion_proceso["explotaciones"][exploit][puerto] == -1:
                    explotacion_temporal[1] = "Fracaso"

            if explotacion_temporal[1] == "Exitoso":
                grafica[0] += 1
                
            if explotacion_temporal[1] == "Inconcluso":
                grafica[1] += 1

            if explotacion_temporal[1] == "Fracaso":
                grafica[2] += 1

            explotacion.append(explotacion_temporal.copy())
        self.crear_grafica_explotacion(grafica, reporte)
        analisis = self.crear_explotacion(explotacion, reporte_relativo)
        self.peticion_reporte["analisis"].append(analisis)


    def validar_campo(self, peticion, valor):
        '''
            Funcion que valida la existencia del campo en algun diccionario

            Parametros
            ----------
            peticion : dict
                diccionario a buscar el campo
            valor : str
                cadena que sera buscada dentro del diccionario
        '''
        if valor in peticion:
            return peticion[valor]
        return "NA"

    def obtener_cifrados_debiles(self, peticion_proceso):
        '''
            Funcion que regresa los cifrados debiles en el sitio

            Parametros
            ----------
            peticion_proceso : dict
                diccionario que contiene el resultado del analisis
        '''
        cifrados = 0
        if len(peticion_proceso["analisis"]["cifrados"]) != 0:
            for cifrado in peticion_proceso["analisis"]["cifrados"]:
                if peticion_proceso["analisis"]["cifrados"][cifrado].lower() == "debil":
                    cifrados += 1
        return cifrados

    def obtener_vulnerabilidades(self, peticion_proceso):
        '''
            Funcion que regresa el total de vulnerabilidades y posibles vulnerabilidades realizadas por el fuzzing
            Parametros
            ----------
            peticion_proceso : dict
                diccionario que contiene el resultado del analisis
        '''
        vulnerabilidades = 0
        posibles_vulnerabilidades = 0
        for pagina in peticion_proceso["analisis"]["paginas"]:
            for tipo in pagina:
                if tipo == "forms":
                    for form in pagina[tipo]:
                        for resultados in pagina[tipo][form]:
                            for ataque in ["xss","sqli","sqli_blind","sqli_blind_time","posible_vulnerabilidad_comun","posible_vulnerabilidad_xss"]:
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
                                    elif ataque == "posible_vulnerabilidad_xss":
                                        posibles_vulnerabilidades += 1

                elif tipo == "vulnerabilidades":
                    for vulnerabilidad in pagina[tipo]:
                        for resultado in pagina[tipo][vulnerabilidad]:
                            if resultado["lfi"] == True:
                                vulnerabilidades += 1
                            elif resultado["posible_vulnerabilidad"]:
                                posibles_vulnerabilidades += 1

                elif tipo == "forms_selenium":
                    for form in pagina[tipo]:
                        for resultado in pagina[tipo][form]:
                            if resultado["xss"] == True:
                                vulnerabilidades += 1

                elif tipo == "forms_upload":
                    for form in pagina[tipo]:
                        for resultado in pagina[tipo][form]:
                            if resultado["upload"] == True:
                                vulnerabilidades += 1
                            elif resultado["posible_vulnerabilidad_comun"] == True:
                                posibles_vulnerabilidades += 1

        return vulnerabilidades, posibles_vulnerabilidades

    def obtener_explotaciones(self, peticion_proceso):
        '''
            Funcion que regresa el total de explotaciones exitosas

            Parametros
            ----------
            peticion_proceso : dict
                diccionario que contiene el resultado del analisis
        '''
        explotacion = 0
        for exploit in peticion_proceso["explotaciones"]:
            for puerto in peticion_proceso["explotaciones"][exploit]:
                if peticion_proceso["explotaciones"][exploit][puerto] == 1:
                    explotacion += 1
                    break
        return explotacion

    def obtener_pais(self, peticion_proceso):
        '''
            Funcion que regresa el pais en donde se encuentra el servidor

            Parametros
            ----------
            peticion_proceso : dict
                diccionario que contiene el resultado del analisis
        '''
        pais = peticion_proceso["informacion"]["robtex"]["informacion"]["pais"]
        pais_secundario = peticion_proceso["informacion"]["dnsdumpster"]["host"][0]["pais"]
        if pais == "NA" and pais_secundario != "":
            pais = pais_secundario
        return pais

    def obtener_puertos_grafica(self, peticion_proceso):
        '''
            Funcion que regresa el total de puertos abiertos, cerrados y filtrados

            Parametros
            ----------
            peticion_proceso : dict
                diccionario que contiene el resultado del analisis
        '''
        puertos_generales = []
        puertos_generales.append(len(peticion_proceso["informacion"]["puertos"]["abiertos"]))
        puertos_generales.append(len(peticion_proceso["informacion"]["puertos"]["cerrados"]))
        puertos_generales.append(len(peticion_proceso["informacion"]["puertos"]["filtrados"]))
        return puertos_generales

    def obtener_cifrados_grafica(self, peticion_proceso):
        '''
            Funcion que regresa el total de cifrados debiles, recomendados y seguros

            Parametros
            ----------
            peticion_proceso : dict
                diccionario que contiene el resultado del analisis
        '''
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

    def crear_informacion_general(self, datos_generales):
        '''
            Funcion que regresa el analisis de la informacion general para ser representada en el reporte

            Parametros
            ----------
            datos_generales : array
                nombre y descripcion de los datos en forma de arreglo sobre un arreglo
        '''
        analisis = {
                    "categoria":"",
                    "titulo":"Información general",
                    "grafica":"",
                    "cabecera":["Nombre","Descripción"],
                    "datos":datos_generales,
        }
        return analisis

    def crear_dnsdumpster(self, dnsdumpster):
        '''
            Funcion que regresa el analisis del dnsdumpster para ser representada en el reporte

            Parametros
            ----------
            dnsdumpster : array
                tipo, valor, ip, DNS inverso, país de los datos en forma de arreglo sobre un arreglo
        '''
        analisis = {
            "categoria":"",
            "titulo":"DNS Dumpster",
            "grafica":"",
            "cabecera":["Tipo","Valor","IP", "DNS Inverso", "País"],
            "datos":dnsdumpster
        }
        return analisis

    def crear_robtex(self, robtex):
        '''
            Funcion que regresa el analisis del robtex para ser representada en el reporte

            Parametros
            ----------
            robtex : array
                tipo, dominio, dominio o ip de los datos en forma de arreglo sobre un arreglo
        '''
        analisis = {
                    "categoria":"",
                    "titulo":"Robtex",
                    "grafica":"",
                    "cabecera":["Tipo","Dominio","Dominio - IP"],
                    "datos":robtex
        }
        return analisis

    def crear_b_f_l(self, bfl):
        '''
            Funcion que regresa el analisis de las bibliotecas, lenguajes y frameworks para ser representada en el reporte

            Parametros
            ----------
            bfl : array
                tipo, nombre, version de los datos en forma de arreglo sobre un arreglo
        '''
        analisis = {
                    "categoria":"",
                    "titulo":"Bibliotecas, Frameworks, Lenguajes",
                    "grafica":"",
                    "cabecera":["Tipo","Nombre", "Versión"],
                    "datos":bfl
        }
        return analisis

    def crear_plugins(self, plugins):
        '''
            Funcion que regresa el analisis de plugins para ser representada en el reporte

            Parametros
            ----------
            plugins : array
                nombre de los datos en forma de arreglo sobre un arreglo
        '''
        analisis = {
                    "categoria":"",
                    "titulo":"Plugins",
                    "grafica":"",
                    "cabecera":["Nombre"],
                    "datos":plugins
        }
        return analisis

    def crear_archivos(self, archivos):
        '''
            Funcion que regresa el analisis de los archivos para ser representada en el reporte

            Parametros
            ----------
            archivos : array
                nombre de los datos en forma de arreglo sobre un arreglo
        '''
        analisis = {
                    "categoria":"",
                    "titulo":"Archivos",
                    "grafica":"",
                    "cabecera":["Nombre"],
                    "datos":archivos
        }
        return analisis

    def crear_google(self, enlaces):
        '''
            Funcion que regresa el analisis de google para ser representada en el reporte

            Parametros
            ----------
            enlaces : array
                tipo y nombre de los datos en forma de arreglo sobre un arreglo
        '''
        analisis = {
                    "categoria":"",
                    "titulo":"Google",
                    "grafica":"",
                    "cabecera":["Tipo","Nombre"],
                    "datos":enlaces
        }
        return analisis

    def crear_bing(self, enlaces):
        '''
            Funcion que regresa el analisis de bing para ser representada en el reporte

            Parametros
            ----------
            enlaces : array
                tipo y nombre de los datos en forma de arreglo sobre un arreglo
        '''
        analisis = {
                    "categoria":"",
                    "titulo":"Bing",
                    "grafica":"",
                    "cabecera":["Tipo","Nombre"],
                    "datos":enlaces
        }
        return analisis

    def crear_cve(self, cve):
        '''
            Funcion que regresa el analisis de los cve para ser representada en el reporte

            Parametros
            ----------
            cve : array
                nombre de los datos en forma de arreglo sobre un arreglo
        '''
        analisis = {
                    "categoria":"",
                    "titulo":"CVE",
                    "grafica":"",
                    "cabecera":["Nombre"],
                    "datos":cve
        }
        return analisis

    def crear_headers(self, headers):
        '''
            Funcion que regresa el analisis de los headers para ser representada en el reporte

            Parametros
            ----------
            headers : array
                nombre de los datos en forma de arreglo sobre un arreglo
        '''
        analisis = {
                    "categoria":"",
                    "titulo":"Headers",
                    "grafica":"",
                    "cabecera":["Nombre"],
                    "datos":headers
        }
        return analisis
    
    def crear_vulnerabilidades_pagina(self, vulnerabilidades):
        '''
            Funcion que regresa el analisis de las vulnerabilidades por pagina para ser representada en el reporte junto con su grafica

            Parametros
            ----------
            cifrados : : array
                pagina, xss, sqli, sqli blind, sqli blind time, lfi, uplaod de los datos en forma de arreglo sobre un arreglo            
        '''
        
        analisis = {
                    "categoria":"",
                    "titulo":"Vulnerabilidades por página",
                    "grafica":"",
                    "cabecera":["Página","XSS","SQLi","SQLi Blind","SQLi Blind Time","LFI","Upload"],
                    "datos":vulnerabilidades
        }
        return analisis

    def crear_posibles_vulnerabilidades(self, vulnerabilidades):
        '''
            Funcion que regresa el analisis de las posibles vulnerabilidades para ser representada en el reporte

            Parametros
            ----------
            vulnerabilidades : : array
                sqli, lfi y upload de los datos en forma de arreglo sobre un arreglo
        '''
        
        analisis = {
                    "categoria":"",
                    "titulo":"Posibles Vulnerabilidades",
                    "grafica":"",
                    "cabecera":["XSS", "SQLi", "LFI","Upload"],
                    "datos":vulnerabilidades
        }
        return analisis


    def crear_puertos(self, puertos_individuales, reporte_relativo):
        '''
            Funcion que regresa el analisis de los puertos de forma individual para ser representada en el reporte

            Parametros
            ----------
            puertos_individuales : array
                resultado de los puertos individuales con relacion a la cabecera
            reporte_relativo : str
                cadena que indica la ruta de la grafica
        '''
        analisis = {
                    "categoria":"",
                    "titulo":"Puertos",
                    "grafica":reporte_relativo,
                    "cabecera":["Tipo","Puerto","Protocolo","Servicio"],
                    "datos":puertos_individuales,
        }
        return analisis

    def crear_cifrados(self, cifrados, reporte_relativo):
        '''
            Funcion que regresa el analisis de los cifrados para ser representada en el reporte junto con su grafica

            Parametros
            ----------
            cifrados : : array
                nombre e interpretacion de los datos en forma de arreglo sobre un arreglo
            reporte_relativo : str
                cadena de la ruta de la grafica
        '''
        analisis = {
                    "categoria":"",
                    "titulo":"Cifrados",
                    "grafica":reporte_relativo,
                    "cabecera":["Nombre","Interpretación"],
                    "datos":cifrados
        }
        return analisis

    def crear_vulnerabilidades(self, vulnerabilidades, reporte_relativo):
        '''
            Funcion que regresa el analisis de las vulnerabilidades para ser representada en el reporte junto con su grafica

            Parametros
            ----------
            vulnerabilidades : : array
                xss, sqli, sqli blind, sqli blind time, lfi, upload de los datos en forma de arreglo sobre un arreglo
            reporte_relativo : str
                cadena de la ruta de la grafica
        '''
        
        analisis = {
                    "categoria":"",
                    "titulo":"Vulnerabilidades",
                    "grafica":reporte_relativo,
                    "cabecera":["XSS","SQLi","SQLi Blind","SQLi Blind Time","LFI","Upload"],
                    "datos":vulnerabilidades
        }
        return analisis

    def crear_explotacion(self, explotacion, reporte_relativo):
        '''
            Funcion que regresa el analisis de las explotaciones para ser representada en el reporte junto con su grafica

            Parametros
            ----------
            cifrados : : array
                nombre y resultado de los datos en forma de arreglo sobre un arreglo
            reporte_relativo : str
                cadena de la ruta de la grafica
        '''
        
        analisis = {
                    "categoria":"",
                    "titulo":"Explotación",
                    "grafica":reporte_relativo,
                    "cabecera":["Nombre", "Resultado"],
                    "datos":explotacion
        }
        return analisis


    def crear_grafica_puertos(self, grafica, reporte_relativo):
        '''
            Funcion que permite crear la grafica de puertos en formato HTML de tipo iframe
            
            Parametros
            ----------
            grafica : array
                arreglo que contiene los datos totales de los puertos abiertos, cerrados y filtrados
            reporte_relativo : str
                cadena en donde se guardara la grafica HTML
        '''
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

    def crear_grafica_vulnerabilidades(self, grafica, reporte):
        '''
            Funcion que permite crear la grafica de puertos en formato HTML de tipo iframe
            
            Parametros
            ----------
            grafica : array
                arreglo que contiene los datos totales del fuzzing xss, sqli, sqli_blind, sqli_blind_time, lfi y upload
            reporte_relativo : str
                cadena en donde se guardara la grafica HTML
        '''
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

    def crear_grafica_cifrados(self, grafica, reporte_relativo):
        '''
            Funcion que permite crear la grafica de cifrados en formato HTML de tipo iframe
            
            Parametros
            ----------
            grafica : array
                arreglo que contiene los datos totales de los cifrados debiles, recomendados y seguros
            reporte_relativo : str
                cadena en donde se guardara la grafica HTML
        '''
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

    def crear_grafica_explotacion(self, grafica, reporte):
        ''''
            Funcion que permite crear la grafica de puertos en formato HTML de tipo iframe
            
            Parametros
            ----------
            grafica : array
                arreglo que contiene los datos totales de las explotaciones en los resultados de exito, fracaso e inconcluso
            reporte_relativo : str
                cadena en donde se guardara la grafica HTML
        '''
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


    def reportes_csv_crear(self):
        '''
            Funcion que crea el CSV a partir del reporte

            Parametros
            ----------
            peticion_reporte : dict
                diccionario que ya contiene todo el reporte para crear el HTML
            ruta_previa : str
                cadena que tiene la ruta para guardar el archivo
        '''
        ruta = "{0}/cvs".format(self.ruta_previa)
        try:
            mkdir(ruta)
        except FileExistsError:
            pass
        for cvs in self.peticion_reporte["analisis"]:
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

    def reportes_json_crear(self):
        '''
            Funcion que crea el JSON a partir del reporte

            Parametros
            ----------
            peticion_reporte : dict
                diccionario que ya contiene todo el reporte para crear el HTML
            ruta_previa : str
                cadena que tiene la ruta para guardar el archivo
        '''
        ruta = "{0}/json".format(self.ruta_previa)
        try:
            mkdir(ruta)
        except FileExistsError:
            pass
        archivo = "{0}/analisis.json".format(ruta)
        with open(archivo, "w") as reporte_archivo:
            reporte_archivo.write(json.dumps(self.peticion_proceso))

class Utileria():
    '''
        Clase que sirve para validar datos, volcar consultas, peticiones y exploits

        .........

        Atributos
        ---------
        con = Conector()
            permite la conexion con Mongo

        Metodos
        -------
        proximos_peticion_escaneos():
            Función que hace un dump del objeto "cola" para extraer todos los sitios pendientes por hacer el analisis
            y el sitio actual

        consulta_peticion_volcado():  
            Función que hace una peticion al servidor Mongo para obtener un conteo de los analisis obtenidos, la fecha del ultimo analisis y un diccionario de
            sitios con sus fechas
            
        exploits_peticion_volcado():
            Función que realiza una conexión con Mongo para hacer un dump de nombres de exploits
            
        validar_json_ejecucion(peticion):
            Funcion que valida que contengan los campos necesarios para ejecutar la aplicacion
            
        validar_json_sitio(peticion):
            Funcion que valida que los datos del sitio, profundidad y puertos sean validos
            esto sirve para el correcto funcionamiento de la aplicacion
            
        validar_json_archivo(peticion):
            Funcion que valida que el campo sitio del json sea un archivo
        
    '''
    def __init__(self):
        self.con = Conector()

    def proximos_peticion_escaneos(self):
        '''
            Función que hace un dump del objeto "cola" para extraer todos los sitios pendientes por hacer el analisis
            y el sitio actual
        '''
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

    def consulta_peticion_volcado(self):
        '''
            Función que hace una peticion al servidor Mongo para obtener un conteo de los analisis obtenidos, la fecha del ultimo analisis y un diccionario de
            sitios con sus fechas
        '''
        
        consulta = {}
        analisis_totales = self.con.obtener_analisis_totales()
        ultima_fecha = self.con.obtener_ultima_fecha()
        analisis = self.con.obtener_analisis_generales()

        consulta["analisis_totales"] = analisis_totales
        consulta["ultima_fecha"] = ultima_fecha
        consulta["analisis"] = analisis
        respueta_json = consulta
        print(respueta_json)
        respueta_json["status"] = "Reportes cargados"
        return respueta_json

    def exploits_peticion_volcado(self):
        ''''
            Función que realiza una conexión con Mongo para hacer un dump de nombres de exploits
        '''
        volcado = self.con.exploit_volcado()
        if len(volcado["exploits"]) == 0:
            return json.dumps({"status":"No se encotraron Exploits"})
        volcado["status"] = "Exploits cargados"
        return volcado

    def validar_json_ejecucion(self, peticion):
        '''
            Funcion que valida que contengan los campos necesarios para ejecutar la aplicacion

            Parametros
            ----------
            peticion : dict
                contiene la peticion original enviada al servidor
        '''
        if "sitio" in peticion and "cookie" in peticion and "profundidad" in peticion and "redireccionamiento" in peticion and "lista_negra" in peticion and "puertos" in peticion:
            return True
        return False

    def validar_json_sitio(self, peticion):
        '''
            Funcion que valida que los datos del sitio, profundidad y puertos sean validos
            esto sirve para el correcto funcionamiento de la aplicacion

            Parametros
            ----------
            peticion : dict
                contiene la peticion original enviada al servidor
        '''
        try:
            sitio = peticion["sitio"]
            requests.get(sitio, verify=False)
        except Exception as e:
            print("No hay conexion a Internet o el sitio no es valido")
            return False
        
        try:
            profundidad = int(peticion["profundidad"])
            if profundidad < 1 or profundidad > 3:
                peticion["profundidad"] = "2"
        except:
            peticion["profundidad"] = "2"
        
        try:
            puertos = int(peticion["puertos"]["final"])
            if puertos < 1 or puertos > 65536:
                peticion["puertos"]["final"] = "1"
        except:
            peticion["puertos"]["final"] = "2"

        return True

    def validar_json_archivo(self, peticion):
        '''
            Funcion que valida que el campo sitio del json sea un archivo

            Parametros
            ----------
            peticion : dict
                contiene la peticion original enviada al servidor
        '''
        if "archivo" in peticion:
            sitios = peticion["archivo"]
            try:
                sitios = sitios.split("base64,")[1]
                sitios = b64decode(sitios)
                if sitios == b"":
                    return ""
                return sitios.decode("ISO-8859-1").strip()
            except:
                return ""

class Exploit():
    '''
        Clase que permite interactuar con los exploits, ya sea con crear, consultar(editar), actualizar o eliminar

        .........

        Atributos
        ---------
        peticion : dict
            diccionario que contiene los datos del exploit para crearlo, consultarlo, actualizar o eliminar

        con : Conector
            objeto que permite la interaccion con Mongo

        Metodos
        -------
        exploits_peticion_crear():
            Funcion que llama a las funciones del modulo "explotacion" para crear el exploit y guardar una referencia en Mongo
            
        exploits_peticion_editar():
            Realiza una conexión con Mongo para realizar una consulta de edicion de un exploit
            
        exploits_peticion_eliminar():
            Realiza una conexión con Mongo para realizar una consulta de eliminación de un exploit
        
    '''
    def __init__(self, peticion):
        self.peticion = peticion
        self.con = Conector()

    def exploits_peticion_crear(self):
        '''
            Función que llama a las funciones del modulo "explotacion" para crear el exploit y guardar una referencia en Mongo
        '''
        exploit = exp.execute(self.peticion)
        self.con.exploit_insertar_o_actualizar_registro(exploit)
        return json.dumps({"status":"Exploit enviado"})

    def exploits_peticion_editar(self):
        '''
            Realiza una conexión con Mongo para realizar una consulta de edicion de un exploit
        '''
        registro = self.con.exploit_consulta_registro(self.peticion)
        if registro == None:
            return json.dumps({"estado":"error"})
        return registro

    def exploits_peticion_eliminar(self):
        '''
            Realiza una conexión con Mongo para realizar una consulta de eliminación de un exploit
        '''
        ruta = "./files/" + self.peticion["exploit"]
        try:
            remove(ruta)
        except FileNotFoundError:
            print("Exploit no encontrado")
        self.con.exploit_eliminar_registro(self.peticion)
        return json.dumps({"status":"Exploit eliminado"})

# Variable de encolamiento
cola = Encolamiento()

'''
    Rutas
'''
# Plantilla principal
@app.route("/")
def principal():
    '''
        Funcion que sirve para cargar la plantilla principal HTML
    '''
    return render_template("app.html")

@app.route("/proximos-escaneos", methods=["GET","POST"])
def proximos_escaneos():
    '''
        Funcion que sirve para obtener los escaneos pendientes a realizar, los regresa en formato JSON
    '''
    if request.method == "POST":
        utileria = Utileria()
        respuesta = utileria.proximos_peticion_escaneos()
        return respuesta

@app.route("/ejecucion", methods=["GET","POST"])
def ejecucion():
    '''
        Funcion que realiza la ejecución del analisis de sitios, la cual verifica el tipo de dato ingresado y los datos internos
        esta peticion es guardada dentro la cola
    '''
    if request.method == "POST":
        utileria = Utileria()
        peticion_json = request.json
        if utileria.validar_json_ejecucion(peticion_json):
            sitios_decodificados = utileria.validar_json_archivo(peticion_json) 
            if sitios_decodificados != "":
                for sitio in sitios_decodificados.split("\n"):
                    peticion_temp = peticion_json.copy()
                    peticion_temp["sitio"] = sitio
                    peticion_temp["archivo"] = ""
                    respuesta = cola.add_peticion(peticion_temp)
            else:
                respuesta = cola.add_peticion(peticion_json)
            return respuesta

        else:
            return json.loads({"estatus":"error"})
    if request.method == "GET":
        return "GET no"

### Seccion de creacion de reportes
@app.route("/consulta-reporte", methods=["GET","POST"])
def consulta_reporte():
    '''
        Funcion que llama a la ejecucion del reporte de algun sitio
    '''
    if request.method == "POST":
        peticion_json = request.get_json()
        ireporte = Reportes(peticion_json)
        respuesta = ireporte.consulta_peticion_reporte()
        return respuesta

@app.route("/reporte")
def reporte():
    '''
        Funcion que sirve para renderizar y mostrar el reporte
    '''
    return render_template("reporte.html")

@app.route("/reporte-eliminar", methods=["GET","POST"])
def reporte_eliminar():
    '''
        Funcion que llama a la ejecucion del reporte de algun sitio
    '''
    if request.method == "POST":
        peticion_json = request.get_json()
        ireporte = Reportes(peticion_json)
        respuesta = ireporte.eliminar_reporte()
        return respuesta

@app.route("/reporte-informacion")
def reporte_grafica_informacion():
    '''
        Funcion que sirve para renderizar la grafica de informacion
    '''
    return render_template("ifram_grafica_informacion.html")

@app.route("/reporte-analisis")
def reporte_grafica_analisis():
    '''
        Funcion que sirve para renderizar la grafica de analisis
    '''
    return render_template("ifram_grafica_analisis.html")

@app.route("/reporte-fuzzing")
def reporte_grafica_fuzzing():
    '''
        Funcion que sirve para renderizar la grafica de fuzzing
    '''
    return render_template("ifram_grafica_fuzzing.html")

@app.route("/reporte-explotacion")
def reporte_grafica_explotacion():
    '''
        Funcion que sirve para renderizar la grafica de explotacion
    '''
    return render_template("ifram_grafica_explotacion.html")
### Fin de seccion

### Seccion de volcados
@app.route("/consulta-volcado", methods=["GET","POST"])
def consulta_volcado():
    '''
        Funcion que regresa un conjunto de datos para la visualizacion del ultimo analisis, total de sitios analizados y el nombre/fecha de los sitios
    '''
    if request.method == "POST":
        utileria = Utileria()
        respuesta = utileria.consulta_peticion_volcado()
        return respuesta

@app.route("/exploits-volcado", methods=["GET","POST"])
def exploits_volcado():
    '''
        Funcion que regresa una lista de nombres de exploits
    '''
    if request.method == "POST":
        utileria = Utileria()
        respuesta = utileria.exploits_peticion_volcado()
        return respuesta
    if request.method == "GET":
        return "GET no"
### Fin de seccion

### Seccion de creacion de exploits
@app.route("/exploits-crear", methods=["GET","POST"])
def exploits():
    '''
        Funcion que guarda un exploit
    '''
    if request.method == "POST":
        
        peticion_json = request.get_json()
        iexploit = Exploit(peticion_json)
        respuesta = iexploit.exploits_peticion_crear()
        return respuesta
    if request.method == "GET":
        return "GET no"

@app.route("/exploits-editar", methods=["GET","POST"])
def exploits_editar():
    '''
        Funcion que regresa un exploit con todas sus caracteristicas recibiendo como entrada el nombre del exploit
    '''
    if request.method == "POST":
        peticion_json = request.get_json()
        iexploit = Exploit(peticion_json)
        respuesta = iexploit.exploits_peticion_editar()
        return respuesta
    if request.method == "GET":
        return "GET no"

@app.route("/exploits-eliminar", methods=["GET","POST"])
def exploits_eliminar():
    '''
        Funcion que elimina un exploit recibiendo como entrada el nombre del exploit
    '''
    if request.method == "POST":
        
        peticion_json = request.get_json()
        iexploit = Exploit(peticion_json)
        respuesta = iexploit.exploits_peticion_eliminar()
        return respuesta
    if request.method == "GET":
        return "GET no"
### Fin de seccion

@app.before_first_request
def iniciar_ciclo_analisis():
    '''
        Funcion que permite crear un hijo para realizar el proceso de iterar la cola en busca de peticiones
    '''
    thread = threading.Thread(target=ciclo_analisis)
    thread.start()

def ciclo_analisis():
    '''
        Funcion que itera la cola en busca de peticiones almacenadas
    '''
    while True:
        peticiones = cola.len_peticion()
        print("Obteniendo peticiones\nPeticiones en cola ->",peticiones)
        if peticiones > 0:
            peticion = cola.pop_peticion()
            # try:
            #     ejecucion_analisis(peticion)
            # except Exception as e:
            #     print("Ocurrió un error bro", e)
            Masivo(peticion)
        cola.reset_peticion_actual()
        sleep(2)

def iniciar_ciclo_primera_peticion():
    '''
        Funcion que crea un hilo para activar el funcionamiento base de la cola
    '''
    thread = threading.Thread(target=ciclo_primera_peticion)
    thread.start()

def ciclo_primera_peticion():
    '''
        Funcion que hacer una peticion a localhost para activar el hilo de la cola
    '''
    server_abajo = True
    while server_abajo:
        try:
            peticion = requests.get("http://0.0.0.0:3000/")
            if peticion.status_code == 200:
                server_abajo = False
        except:
            pass

if __name__ == "__main__":
    '''
        Funcion principal que sirve para lanzar la aplicacion Flask
    '''
    iniciar_ciclo_primera_peticion()
    app.run(host='0.0.0.0', port=3000, debug=True)