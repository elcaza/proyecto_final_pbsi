import re, requests, json
from socket import timeout
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from fake_useragent import UserAgent
from os import path, listdir
from random import choice
from string import ascii_letters
import concurrent.futures
import requests
from time import sleep
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from selenium import webdriver
from selenium.common.exceptions import NoAlertPresentException, UnexpectedAlertPresentException, NoSuchElementException, TimeoutException, ElementNotInteractableException, WebDriverException, JavascriptException, InvalidCookieDomainException

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class Validaciones():
    '''
        Clase que representa las validaciones de los diferentes tipos de ataques

        ...

        Atributos
        ----------
        ruta : str
            ruta de los archivos de configuración

        Metodos
        -------
        validar_tipo_input(tipo):
            valida si el tipo de input es escribible

        validar_tamanio_input(tamanio):
            valida que el input tenga un tamaño mayor a 0

        validar_tamanio_input_selenium(tamanio):
            valida que el input tenga un tamaño mayor a 0 pero con Selenium

        validar_xss(resultado, payload):
            valida que se encuentre el payload de XSS en el cuerpo del requests

        validar_xss_selenium(driver):
            valida que se encuentre la palabra clave XSS DETECTADO en una alerta

        validar_upload(driver):
            valida que se no se encuentren fallos o una cadena de exito

        validar_upload_error(driver):
            valida que se encuentren cadenas de errores comunes del tipo file upload

        validar_sqli(resultado, payload):
            valida que se encuentren palabras clave del diccionario sqli_blind.json

        validar_sqli_blind_time(resultado, payload):
            valida que el tiempo de respuesta sea mayor o igual a 10

        validar_sqli_blind(resultado_correcto,resultado_incorrecto,resultado_payload,payload):
            valida que el ataque de tipo sqli blind sea exitoso

        validar_lfi(resultado):
            valida que se encuentren cadenas del archivo lfi.json

        validar_codigo(resultado):
            valida que el codigo de respuesta sea valido

        validar_errores_comunes(resultado):
            valida que se encuentre errores comunes de las peticione de requests

        validar_errores_comunes_selenium(driver):
            valida que se encuentren errores comunes de las peticiones con Selenium

        validar_error_lfi(resultado):
            valida que se encuentren errores de LFI

    '''

    def __init__(self):
        self.ruta = path.abspath(path.dirname(__file__))

    def validar_tipo_input(self, tipo):
        '''
            valida si el tipo de input es escribible

            si se encuentran el tipo en "text", "password" o "submit" regresa verdadero

            Parametros
            ----------
            tipo : str

        '''
        if tipo == "text" or tipo == "password" or tipo == "submit" or tipo == None:
            return True
        return False

    def validar_tamanio_input(self, tamanio):
        '''
            valida que el input tenga un tamaño mayor a 0

            Parametros
            ----------
            tamanio : int
        '''

        if tamanio:
            try:
                tamanio = int(tamanio)
                if tamanio > 0:
                    return True
            except:
                return False
        return False

    def validar_tamanio_input_selenium(self, tamanio):
        '''
            valida que el input tenga un tamaño mayor a 0

            Parametros
            ----------
            tamanio : dict
        '''

        altura = tamanio["height"]
        anchura = tamanio["width"]
        if altura > 0 and anchura > 0:
            return True
        return False

    def validar_xss(self, resultado, payload):
        '''
            valida que se encuentre el payload de XSS en el cuerpo del requests

            Parametros
            ----------
            resultado : requests
            payload : str
        '''
        texto = resultado.text
        payload = re.escape(payload)
        resultado = re.search(payload,texto)
        if resultado:
            return True
        return False

    def validar_xss_selenium(self, driver):
        '''
            valida que se encuentre la palabra clave XSS DETECTADO en una alerta

            Parametros
            ----------
            driver : webdriver
        '''
        try:
            alerta = driver.switch_to.alert
            if alerta.text == "XSS DETECTADO":
                alerta.accept()
                return True
            alerta.accept()
            return False
        except NoAlertPresentException:
            return False

    def validar_upload(self, driver):
        '''
            valida que se no se encuentren fallos o una cadena de exito

            Parametros
            ----------
            driver : webdriver
        '''
        try:
            ruta = "{0}{1}".format(self.ruta,"/validacion_upload.json")
            with open(ruta,"r") as errores:
                self.errores_comunes = json.load(errores)
        except FileNotFoundError:
            self.errores_comunes = []

        texto = driver.page_source
        for error in self.errores_comunes:
            if re.search(re.escape(error),texto):
                return True
        return False

    def validar_upload_error(self, driver):
        '''
            valida que se encuentren cadenas de errores comunes del tipo file upload

            Parametros
            ----------
            driver : webdriver
        '''
        try:
            ruta = "{0}{1}".format(self.ruta,"/validacion_errores_upload.json")
            with open(ruta,"r") as errores:
                self.errores_comunes = json.load(errores)
        except FileNotFoundError:
            self.errores_comunes = []

        texto = driver.page_source
        for error in self.errores_comunes:
            if re.search(re.escape(error),texto):
                return False
        return True

    def validar_sqli(self, resultado, payload):
        '''
            valida que se encuentren palabras clave del diccionario sqli.json

            Parametros
            ----------
            resultado : requests
            payload : str
        '''
        try:
            ruta = "{0}{1}".format(self.ruta,"/validacion_sqli.json")
            with open(ruta,"r") as errores:
                self.cadenas_sqli = json.load(errores)
        except FileNotFoundError:
            self.cadenas_sqli = []
        texto = resultado.text

        texto = resultado.text
        for palabra in self.cadenas_sqli:
            palabra_escapada = re.escape(palabra)
            resultado = re.search(palabra_escapada,texto)
            if resultado:
                return True
        return False

    def validar_sqli_blind_time(self, resultado, payload):
        '''
            valida que el tiempo de respuesta sea mayor o igual a 10

            Parametros
            ----------
            resultado : requests
            payload : str
        '''
        tiempo = resultado.elapsed.seconds
        if tiempo >= 10:
            return True
        return False
        
    def validar_sqli_blind(self, resultado_correcto,resultado_incorrecto,resultado_payload,payload):
        '''
            valida que el ataque de tipo sqli blind sea exitoso

            Parametros
            ----------
            resultado : requests
            payload : str
        '''
        texto_correcto = resultado_correcto.text
        texto_incorrecto = resultado_incorrecto.text
        texto_payload = resultado_payload.text
        if texto_payload == texto_correcto and texto_correcto != texto_incorrecto:
            return True

        codigo_correcto = resultado_correcto.status_code
        codigo_incorrecto = resultado_incorrecto.status_code
        codigo_payload = resultado_payload.status_code

        if codigo_payload == codigo_correcto and codigo_correcto != codigo_incorrecto:
            return True

        return False

    def validar_lfi(self, resultado):
        '''
            valida que se encuentren cadenas del archivo lfi.json

            Parametros
            ----------
            resultado : requests
        '''
        try:
            ruta = "{0}{1}".format(self.ruta,"/validacion_lfi.json")
            with open(ruta,"r") as errores:
                self.cadenas_lfi = json.load(errores)

        except FileNotFoundError:
            self.cadenas_lfi = []

        texto = resultado.text
        
        for cadena in self.cadenas_lfi:
            passwd = re.search(cadena,texto)
            if passwd:
                return True
        return False

    def validar_codigo(self, resultado):
        '''
            valida que el codigo de respuesta sea valido

            este codigo no pertenecer a la familia 500

            Parametros
            ----------
            resultado : str
        '''
        codigo = resultado.status_code
        if codigo >= 500 and codigo <=599:
            return codigo,True
        return codigo,False

    def validar_errores_comunes(self, resultado):
        '''
            valida que se encuentre errores comunes de las peticione de requests

            Parametros
            ----------
            resultado : requests
        '''
        try:
            ruta = "{0}{1}".format(self.ruta,"/validacion_errores_comunes.json")
            with open(ruta,"r") as errores:
                self.errores_comunes = json.load(errores)
        except FileNotFoundError:
            self.errores_comunes = []

        texto = resultado.text
        for error in self.errores_comunes:
            if re.search(re.escape(error),texto):
                return True
        return False

    def validar_errores_comunes_selenium(self, driver):
        '''
            valida que se encuentren errores comunes de las peticiones con Selenium

            Parametros
            ----------
            driver : webdriver
        '''
        try:
            ruta = "{0}{1}".format(self.ruta,"/validacion_errores_comunes.json")
            with open(ruta,"r") as errores:
                self.errores_comunes = json.load(errores)
        except FileNotFoundError:
            self.errores_comunes = []

        texto = driver.page_source
        for error in self.errores_comunes:
            if re.search(re.escape(error),texto):
                return True
        return False

    def validar_error_lfi(self, resultado):
        '''
            valida que se encuentren errores de LFI

            Parametros
            ----------
            resultado : requests
        '''
        try:
            ruta = "{0}{1}".format(self.ruta,"/validacion_errores_lfi.json")
            with open(ruta,"r") as errores:
                self.errores_lfi = json.load(errores)
        except FileNotFoundError:
            self.errores_lfi = []

        texto = resultado.text
        for error in self.errores_lfi:
            if re.search(re.escape(error),texto):
                return True
        return False

class Pagina():

    '''
        Clase que realiza el fuzzing de XSS, SQLi, LFI, Upload a la página proporcionada

        ...
        
        Atributos
        ---------
        url : str
            url que contiene la página

        session : requests.session
            objeto que permite realizar las peticiones estaticas

        regex_patron : str
            expresion regular para detectar las variables a iterar

        user_agent : UserAgent
            objeto que permite obtener un user agent nuevo

        ruta : str
            ruta de los archivos de ataques

        validaciones : Validaciones
            objeto para validar los ataques

        json_fuzzing : dict
            json que se obtiene al realizar el fuzzing

        payload_lista_xss : array
            guardara el archivo xss.json

        payload_lista_lfi : array
            guardara el archivo lfi.json
            
        payload_lista_lfi_tipos : array
            guardara el archivo lfi_tipos.json

        payload_lista_sqli : array
            guardara todas las combinaciones de sqli almacenadas dentro del archivo sqli.json

        payload_lista_sqli_blind : array
            guardara el archivo sqli_blind.json

        payload_lista_sqli_blind_time : array
            guardara el archivo sqli_blind_time.json

        lista_archivos : array
            guardara las rutas de los archivos del ataque file upload

        formularios : dict
            guardara todos los formularios de la pagina
        ...
        
        Metodos
        -------
        enviar_peticion_selenium(inputs):
            envia la petición de selenium con el payload cargado en los inputs

        enviar_peticion_get(url_cargada):
            envia la peticón de requests por get con el payload cargado en los inputs

        cargar_cookies_selenium(driver):
            carga las cookies obtenidas en selenium

        obtener_etiquetas_selenium(driver, form):
            obtiener las etiquetas de los inputs, forms y textareas de selenium

        enviar_peticion_post(url_cargada, data):
            envia la peticón de requests por post con el payload cargado en los inputs

        cadena_aleatoria():
            regresa una cadena aleatoria

        enviar_validacion_comun(resultado, json_temporal={}, form={}, posicion=0, lfi=False):
            envia la validacion de errores comunes al objeto

        enviar_peticiones_xss_sqli_sqliT(lista_payload, funcion_validadora, tipo):
            envia las peticiones de los ataques xss, sqli y sqli blind time

        obtener_nombre_etiqueta(nombre_etiqueta, id_etiqueta, nombre_temporal, tipo = ""):
            obtiene el nombre de las etiquetas de las peticiones de requests

        convertir_cookie(cookie):
            convierte las cookies obtenidas en cookies para requests y selenium

        combinaciones_xss():
            obtiene todas las combinaciones posibles de xss

        combinaciones_lfi():
            obtiene todas las combinaciones posibles de lfi

        combinaciones_sqli():
            obtiene todas las combinaciones posibles de sqli

        combinaciones_sqli_blind():
            obtiene todas las combinaciones posibles de sqli_blind

        combinaciones_sqli_blind_time():
            obtiene todas las combinaciones posibles de sqli_blind_time

        combinaciones_upload():
            obtiene todas las combinaciones posibles de upload

        peticiones_xss():
            carga a la funcion enviar_peticiones_xss_sqli_sqliT con los valores respectivos del xss

        peticiones_sqli():
            carga a la funcion enviar_peticiones_xss_sqli_sqliT con los valores respectivos del sqli

        peticiones_sqli_blind():
            envia conjuntos de peticiones de sqli blind para validar la existencia de la serie

        peticiones_sqli_blind_time():
            carga a la funcion enviar_peticiones_xss_sqli_sqliT con los valores respectivos del sqli blind time

        peticiones_lfi():
            envia peticiones lfi por pagina y no por parametros

        peticiones_selenium_xss():
            configura el webdriver para enviar peticiones xss

        peticiones_selenium_upload():
            configura el webdriver para enviar peticiones upload

        enviar_peticiones_selenium_upload():
            envia las peticiones con el archivo payload upload en los parametros

        enviar_peticiones_selenium_xss():
            envia las peticiones con el payload xss en los parametros

        set_opciones_selenium():
            configura las opciones del webdriver

        set_peticion(json_temporal, carga, form, metodo):
            crea el esquema de la peticion por formulario para ser guardada dentro del json

        set_peticion_lfi(json_temporal, url, carga, metodo):
            crea el esquema de la peticion por pagina para ser guardada dentro del json

        set_formularios():
            obtiene todos los formularios

        set_headers():
            crea los headers necesarios

        get_formularios():
            obtiene los formularios

        get_json_fuzzing():
            obtiene el json de la informacion procesada

        execute():
            lanza el fuzzing      
    '''
    def __init__(self, parametros):
        self.url = parametros["url"]
        print(self.url)
        self.tiempo_espera = int(parametros["tiempo_espera"])
        self.sesion = requests.session()
        self.regex_patron = r"\{(.*)\}"
        self.user_agent = UserAgent()
        self.ruta = path.abspath(path.dirname(__file__))
        self.validaciones = Validaciones()
        self.json_fuzzing = {"forms":{}, "url":self.url}
        self.convertir_cookie(parametros["cookie"])
        self.set_headers()
        self.set_formularios()
        self.set_opciones_selenium()
        self.combinaciones_xss()
        self.combinaciones_lfi()
        self.combinaciones_sqli()
        self.combinaciones_sqli_blind()
        self.combinaciones_sqli_blind_time()
        self.combinaciones_upload()
        
    def enviar_peticion_selenium(self, inputs):
        '''
            envia la petición de selenium con el payload cargado en los inputs

            itera sobre los inputs hasta encontrar el input de tipo submit, una vez encontrado da click

            Parametros
            ----------
            inputs : array[WebElements]
        '''
        for input_unico in inputs:
            tamanio_input = input_unico.size
            if input_unico.get_attribute("type").lower() == "submit" and self.validaciones.validar_tamanio_input_selenium(tamanio_input):
                input_unico.click()
                break

    def enviar_peticion_get(self, url_cargada):
        '''
            envia la peticón de requests por get con el payload cargado en los inputs

            Parametros
            ----------
            url_cargada : str
        '''
        try:
            sleep(self.tiempo_espera)
            resultado = self.sesion.get(url_cargada,cookies=self.cookies_requests,headers=self.headers,verify=False, timeout=15)
            return resultado
        except:
            return None

    def cargar_cookies_selenium(self, driver):
        '''
            carga las cookies obtenidas en selenium

            Parametros
            ----------
            driver : Webdriver
        '''
        try:
            for cookie in self.cookies_selenium:
                driver.add_cookie(cookie)
        except:
            print("No cookies plx")

    def obtener_etiquetas_selenium(self, driver, form):
        '''
            obtiener las etiquetas de los inputs, forms y textareas de selenium

            Parametros
            ----------
            driver : Webdriver
            form : int
        '''
        for i in range(3):
            try:
                driver.get(self.url)
                forms = driver.find_elements_by_xpath("//form")
                inputs = forms[form].find_elements_by_xpath(".//input")
                textareas = forms[form].find_elements_by_xpath(".//textarea")
                return forms, inputs, textareas
            except:
                if i == 2:
                    return None, None, None
            

    def enviar_peticion_post(self, url_cargada, data):
        '''
            envia la peticón de requests por post con el payload cargado en los inputs

            Parametros
            ----------
            url_cargada : str
            data : dict
        '''
        try:
            sleep(self.tiempo_espera)
            resultado = self.sesion.post(url_cargada,cookies=self.cookies_requests,data=data,verify=False, timeout=15)
            return resultado
        except:
            return None

    def cadena_aleatoria(self):
        '''
            regresa una cadena aleatoria de 8 caracteres
        '''
        return ''.join(choice(ascii_letters) for i in range(8))

    def enviar_validacion_comun(self, resultado, json_temporal={}, form={}, posicion=0, lfi=False):
        '''
            envia la validacion de errores comunes al objeto
            
            obtiene el codigo validado y lo guarda dentro del objeto
            valida el error contra lfi y errores comunes, si este resulto verdadero cambia el valor de posible

            Parametros
            ----------
            resultado : requests
            json_temporal : dict
            form : dict
            posicion : int
            lfi : bool
        '''
        codigo, codigo_bool = self.validaciones.validar_codigo(resultado)

        if codigo_bool:
            if lfi:
                json_temporal["vulnerabilidades"]["lfi"][posicion]["codigo"] = codigo
            else:
                json_temporal["forms"][form][posicion]["codigo"] = codigo

        if lfi:
            if self.validaciones.validar_error_lfi(resultado):
                json_temporal["vulnerabilidades"]["lfi"][posicion]["posible_vulnerabilidad"] = True
        else:
            if self.validaciones.validar_errores_comunes(resultado):
                json_temporal["forms"][form][posicion]["posible_vulnerabilidad_comun"] = True
    
    def enviar_peticiones_xss_sqli_sqliT(self, lista_payload, funcion_validadora, tipo):
        '''
            envia las peticiones de los ataques xss, sqli y sqli blind time

            itera todos los form con sus respectivas entradas
            por cada iteración se itera el payload del ataque
            se envia y valida la respuesta obtenida

            Parametros
            ----------
            lista_payload : array
            funcion_validadora : def
            tipo : str
        '''
        json_temporal = {"forms":{}}
        for form_unico in self.formularios:
            i = 0
            json_temporal["forms"][form_unico] = []
            inputs = self.formularios[form_unico]["inputs"]
            metodo = self.formularios[form_unico]["metodo"]
            if metodo == "get":
                for payload in lista_payload:
                    carga = ""
                    bandera_submit = ""
                    for input_unico in inputs:
                        if input_unico.lower() == "submit":
                            bandera_submit = input_unico
                        else:
                            carga += "{0}={1}&".format(input_unico,payload)
                        
                    if bandera_submit != "":
                        carga += "{0}={1}".format(bandera_submit,"Submit")
                    else:
                        carga = carga[:-1]
                    url_cargada = "{0}?{1}".format(self.formularios[form_unico]["accion"],carga)
                    self.set_peticion(json_temporal, carga, form_unico, metodo)
                    resultado = self.enviar_peticion_get(url_cargada)
                    
                    if resultado is None:
                        continue

                    if funcion_validadora(resultado, payload):
                        json_temporal["forms"][form_unico][i][tipo] = True

                    self.enviar_validacion_comun(resultado, json_temporal, form_unico, i)
                    i += 1

            elif metodo == "post":
                for payload in lista_payload:
                    data = {}
                    bandera_submit = ""
                    for input_unico in inputs:
                        if input_unico.lower() == "submit":
                            bandera_submit = input_unico
                        else:
                            data[input_unico] = payload
                    if bandera_submit != "":
                        data[bandera_submit] = "Submit"
                    url_cargada = self.formularios[form_unico]["accion"]

                    self.set_peticion(json_temporal, data, form_unico, metodo)
                    resultado = self.enviar_peticion_post(url_cargada, data)

                    if resultado is None:
                        continue

                    if funcion_validadora(resultado, payload):
                        if tipo == "xss":
                            json_temporal["forms"][form_unico][i]["posible_vulnerabilidad_xss"] = True
                        else:
                            json_temporal["forms"][form_unico][i][tipo] = True
                    
                    self.enviar_validacion_comun(resultado, json_temporal, form_unico, i)
                    i += 1
        return json_temporal

    def obtener_nombre_etiqueta(self, nombre_etiqueta, id_etiqueta, nombre_temporal, tipo = ""):
        '''
            obtiene el nombre de las etiquetas de las peticiones de requests

            si es de tipo submit regresa el nombre tal cual

            Parametros
            ----------
            nombre_etiqueta : str
            id_etiqueta : str
            nombre_temporal : str
            tipo : str
        '''
        if tipo == "submit" and (id_etiqueta == None or id_etiqueta == "") and (nombre_etiqueta != ""):
            return nombre_etiqueta

        elif tipo == "submit" and (id_etiqueta != None or id_etiqueta != ""):
            return id_etiqueta
        
        elif tipo == "submit":
            return "submit"

        elif id_etiqueta == None or id_etiqueta == "":
            if nombre_etiqueta == None or nombre_etiqueta == "":
                return nombre_temporal
            else:
                return nombre_etiqueta
        else:
            return id_etiqueta

    def convertir_cookie(self, cookie):
        '''
            convierte las cookies obtenidas en cookies para requests y selenium

            separa la cookie por comas
            sepera la subcookie por dos puntos 
            guarda la cookie resultante en selinum y requests

            Parametros
            ----------
            cookie : dict
        '''
        self.cookies_requests = {}
        self.cookies_selenium = []
        if cookie != "":
            if cookie.__contains__(","):
                subcookies = cookie.split(",")
                for subcookie in subcookies:
                    cookie_individual_temporal = subcookie.split(":")
                    try:
                        self.cookies_selenium.append({"name":cookie_individual_temporal[0],"value":cookie_individual_temporal[1]})
                        self.cookies_requests[cookie_individual_temporal[0]] = cookie_individual_temporal[1]
                    except IndexError:
                        print("Coookies invalidas")
                        break
            else:
                cookie_individual_temporal = cookie.split(":")
                try:
                    self.cookies_selenium.append({"name":cookie_individual_temporal[0],"value":cookie_individual_temporal[1]})
                    self.cookies_requests[cookie_individual_temporal[0]] = cookie_individual_temporal[1]
                except IndexError:
                    print("Coookies invalidas")

    def combinaciones_xss(self):
        '''
            obtiene todas las combinaciones posibles de xss
        '''
        try:
            ruta = "{0}{1}".format(self.ruta,"/xss.json")
            with open(ruta,"r") as xss:
                self.payload_lista_xss = json.load(xss)
        except FileNotFoundError:
            self.payload_lista_xss = []

    def combinaciones_lfi(self):
        '''
            obtiene todas las combinaciones posibles de lfi
        '''
        try:
            ruta = "{0}{1}".format(self.ruta,"/lfi.json")
            with open(ruta,"r") as lfi:
                self.payload_lista_lfi = json.load(lfi)
        except FileNotFoundError:
            self.payload_lista_lfi = []

        try: 
            ruta = "{0}{1}".format(self.ruta,"/lfi_tipos.json")
            with open(ruta,"r") as lfi:
                self.payload_lista_lfi_tipos = json.load(lfi)
        except FileNotFoundError:
            self.payload_lista_lfi_tipos = []

    def combinaciones_sqli(self):
        '''
            carga a la funcion enviar_peticiones_xss_sqli_sqliT con los valores respectivos del sqli

            busca la palabra clave entre corchetes {EJEMPLO} para ir la recorriendo una posicion
            dentro de la query

        '''
        try:
            ruta = "{0}{1}".format(self.ruta,"/sqli.json")
            with open(ruta,"r") as sqli:
                sqli = json.load(sqli)

            self.payload_lista_sqli = []
            for sql in sqli:
                payload = []
                clave = re.search(self.regex_patron, sql)
                if clave:
                    clave_completa = clave.group()
                    clave = clave.group(1)
                    for i in range(5):
                        if i == 0:
                            sql_split = sql.split(clave_completa)
                            p = clave
                            self.payload_lista_sqli.append("{0}{1}{2}".format(sql_split[0],p,sql_split[1]))
                        else:
                            for k in range(i+1):
                                if k == 0:
                                    payload.append(clave)
                                else:
                                    payload.append("NULL")

                            for j in range(i+1):
                                if j != 0:
                                    payload[j] = clave
                                    payload[0] = "NULL"
                                else:
                                    payload[0] = clave
                                
                                sql_split = sql.split(clave_completa)
                                p = ",".join(payload)
                                self.payload_lista_sqli.append("{0}{1}{2}".format(sql_split[0],p,sql_split[1]))
                                payload[j] = "NULL"
                        payload.clear()
        except FileNotFoundError:
            self.peticiones_sqli_blind = []

    def combinaciones_sqli_blind(self):
        '''
            obtiene todas las combinaciones posibles de sqli_blind
        '''
        try:
            ruta = "{0}{1}".format(self.ruta,"/sqli_blind.json")
            with open(ruta,"r") as sqli_blind:
                self.payload_lista_sqli_blind = json.load(sqli_blind)
        except FileNotFoundError:
            self.peticiones_sqli_blind = []

    def combinaciones_sqli_blind_time(self):
        '''
            obtiene todas las combinaciones posibles de sqli_blind_time
        '''
        try:
            ruta = "{0}{1}".format(self.ruta,"/sqli_blind_time.json")
            with open(ruta,"r") as sqli_blind_time:
                self.payload_lista_sqli_blind_time = json.load(sqli_blind_time)
        except FileNotFoundError:
            self.payload_lista_sqli_blind_time = []

    def combinaciones_upload(self):
        '''
            obtiene todas las combinaciones posibles de upload

            itera el directorio donde se encuentran los archivos para el ataque de file upload
        '''
        self.lista_archivos = [path.abspath(path.dirname(__file__)) + "/upload_file/" + x for x in listdir("./modules/fuzzing/upload_file")]

    def peticiones_xss(self):
        '''
            carga a la funcion enviar_peticiones_xss_sqli_sqliT con los valores respectivos del xss

        '''
        print("XSS")
        json_temporal = self.enviar_peticiones_xss_sqli_sqliT(self.payload_lista_xss,self.validaciones.validar_xss,"xss")
        return json_temporal

    def peticiones_sqli(self):
        '''
            carga a la funcion enviar_peticiones_xss_sqli_sqliT con los valores respectivos del sqli
        '''
        print("SQLi")
        json_temporal = self.enviar_peticiones_xss_sqli_sqliT(self.payload_lista_sqli,self.validaciones.validar_sqli,"sqli")
        return json_temporal

    def peticiones_sqli_blind(self):
        '''
            envia conjuntos de peticiones de sqli blind para validar la existencia de la serie

            
            itera todos los form con sus respectivas entradas
            por cada iteración se itera el payload del ataque
            este payload consta de tres peticiones, dos correctas y una incorrecta
            se envia y valida la respuesta obtenida con base a las tres respuestas
        '''
        print("SQLi Blind")
        json_temporal = {"forms":{}}
        for form_unico in self.formularios:
            i = 0
            json_temporal["forms"][form_unico] = []
            inputs = self.formularios[form_unico]["inputs"]
            metodo = self.formularios[form_unico]["metodo"]
            if metodo == "get":
                for payload in self.payload_lista_sqli_blind:
                    carga_correcta = ""
                    carga_incorrecta = ""
                    carga_payload = ""
                    bandera_submit = ""
                    for input_unico in inputs:
                        if input_unico.lower() == "submit":
                            bandera_submit = input_unico
                        else:
                            carga_correcta += "{0}={1}&".format(input_unico,payload["correcto"])
                            carga_incorrecta += "{0}={1}&".format(input_unico,payload["incorrecto"])
                            carga_payload += "{0}={1}&".format(input_unico,payload["payload"])
                    
                    if bandera_submit != "":
                        carga_correcta += "{0}={1}".format(bandera_submit,"Submit")
                        carga_incorrecta += "{0}={1}".format(bandera_submit,"Submit")
                        carga_payload += "{0}={1}".format(bandera_submit,"Submit")
                    else:
                        carga_correcta = carga_correcta[:-1]
                        carga_incorrecta = carga_incorrecta[:-1]
                        carga_payload = carga_payload[:-1]
                        
                    url_cargada = "{0}?{1}".format(self.formularios[form_unico]["accion"],carga_correcta)
                    resultado_correcto = self.enviar_peticion_get(url_cargada)
                    url_cargada = "{0}?{1}".format(self.formularios[form_unico]["accion"],carga_incorrecta)
                    resultado_incorrecto = self.enviar_peticion_get(url_cargada)
                    url_cargada = "{0}?{1}".format(self.formularios[form_unico]["accion"],carga_payload)
                    resultado_payload = self.enviar_peticion_get(url_cargada)

                    self.set_peticion(json_temporal, "[Correcto] {0}&[Incorrecto] {1}&[Payload] {2}".format(carga_correcta,carga_incorrecta,carga_payload),form_unico,metodo)

                    if resultado_correcto is None or resultado_payload is None or resultado_incorrecto is None:
                        continue

                    if self.validaciones.validar_sqli_blind(resultado_correcto,resultado_incorrecto,resultado_payload, payload):
                        json_temporal["forms"][form_unico][i]["sqli_blind"] = True

                    self.enviar_validacion_comun(resultado_correcto, json_temporal,form_unico, i)
                    self.enviar_validacion_comun(resultado_incorrecto, json_temporal,form_unico, i)
                    self.enviar_validacion_comun(resultado_payload, json_temporal,form_unico, i)
                    
                    i += 1
            
            elif metodo == "post":
                for payload in self.payload_lista_sqli_blind:
                    data_correcta = {}
                    data_incorrecta = {}
                    data_payload = {}
                    bandera_submit = ""
                    for input_unico in inputs:
                        if input_unico.lower() == "submit":
                            bandera_submit = input_unico
                        else:
                            data_correcta["[Correcto] " + input_unico] = payload["correcto"]
                            data_incorrecta["[Incorrecto] " + input_unico] = payload["incorrecto"]
                            data_payload["[Payload] " + input_unico] = payload["payload"]
                    if bandera_submit != "":
                        data_correcta["[Correcto] " + bandera_submit] = "Submit"
                        data_incorrecta["[Incorrecto] " + bandera_submit] = "Submit"
                        data_payload["[Payload] " + bandera_submit] = "Submit"

                    url_cargada = self.formularios[form_unico]["accion"]
                    resultado_correcto = self.enviar_peticion_post(url_cargada, data_correcta)
                    resultado_incorrecto = self.enviar_peticion_post(url_cargada, data_incorrecta)
                    resultado_payload = self.enviar_peticion_post(url_cargada, data_payload)
                    self.set_peticion(json_temporal, {**data_correcta, **data_incorrecta, **data_payload}, form_unico,metodo)

                    if resultado_correcto is None or resultado_payload is None or resultado_incorrecto is None:
                        continue

                    if self.validaciones.validar_sqli_blind(resultado_correcto,resultado_incorrecto,resultado_payload, payload):
                        json_temporal["forms"][form_unico][i]["sqli_blind"] = True

                    self.enviar_validacion_comun(resultado_correcto, json_temporal,form_unico, i)
                    self.enviar_validacion_comun(resultado_incorrecto, json_temporal,form_unico, i)
                    self.enviar_validacion_comun(resultado_payload, json_temporal,form_unico, i)

                    i += 1
        return json_temporal

    def peticiones_sqli_blind_time(self):
        '''
            carga a la funcion enviar_peticiones_xss_sqli_sqliT con los valores respectivos del sqli blind time
        '''
        print("SQLi Blind Time")
        json_temporal = self.enviar_peticiones_xss_sqli_sqliT(self.payload_lista_sqli_blind_time,self.validaciones.validar_sqli_blind_time,"sqli_blind_time")
        return json_temporal

    def peticiones_lfi(self):
        '''
            envia peticiones lfi por pagina y no por parametros

            busca que la url tenga una variable, si tiene itera sobre ella en busca del archivo /etc/passwd
            de lo contrario hace fuerza bruta en post y get
        '''
        print("LFI")
        json_temporal = {"vulnerabilidades":{"lfi":[]}}
        regex_sin_archivo = r".*\?\w+="
        archivo = re.search(regex_sin_archivo,self.url)
        i = 0
        if archivo:
            for payload in self.payload_lista_lfi:
                url_cargada = "{0}{1}".format(archivo.group(),payload)
                self.set_peticion_lfi(json_temporal, url_cargada, payload, "get")
                resultado = self.enviar_peticion_get(url_cargada)

                if resultado is None:
                        continue

                if self.validaciones.validar_lfi(resultado):
                    json_temporal["vulnerabilidades"]["lfi"][i]["lfi"] = True
                                    
                self.enviar_validacion_comun(resultado,json_temporal,posicion=i,lfi=True)
                i += 1
                
        else:
            for tipo in self.payload_lista_lfi_tipos:
                for payload in self.payload_lista_lfi:
                    url_cargada = "{0}?{1}={2}".format(self.url,tipo,payload)
                    self.set_peticion_lfi(json_temporal, url_cargada, payload,"get")

                    resultado = self.enviar_peticion_get(url_cargada)

                    if resultado is None:
                        continue

                    if self.validaciones.validar_lfi(resultado):
                        json_temporal["vulnerabilidades"]["lfi"][i]["lfi"] = True
                    self.enviar_validacion_comun(resultado,json_temporal,posicion=i,lfi=True)
                    i += 1

        for tipo in self.payload_lista_lfi_tipos:
            data = {}
            for payload in self.payload_lista_lfi:
                data[tipo] = payload
                url_cargada = self.url
                self.set_peticion_lfi(json_temporal, url_cargada, data, "post")
                resultado = self.enviar_peticion_post(url_cargada, data)

                if resultado is None:
                        continue

                if self.validaciones.validar_lfi(resultado):
                    json_temporal["vulnerabilidades"]["lfi"][i]["lfi"] = True
                self.enviar_validacion_comun(resultado,json_temporal,posicion=i,lfi=True)
                i += 1

        return json_temporal
    
    def peticiones_selenium_xss(self):
        '''
            configura el webdriver para enviar peticiones xss
        '''
        self.driver_xss = webdriver.Chrome("/usr/bin/chromedriver",options=self.sin_navegador)
        self.driver_xss.set_page_load_timeout(30)
        try:
            json_forms_selenium = self.enviar_peticiones_selenium_xss()
            self.driver_xss.quit()
            return json_forms_selenium
        except:
            return {"forms_selenium":{}}

    def peticiones_selenium_upload(self):
        '''
            configura el webdriver para enviar peticiones upload
        '''        
        self.driver_upload = webdriver.Chrome("/usr/bin/chromedriver",options=self.sin_navegador)
        self.driver_upload.set_page_load_timeout(30)
        try:
            json_forms_selenium = self.enviar_peticiones_selenium_upload()
            self.driver_upload.quit()
            return json_forms_selenium
        except:
            return {"forms_upload":{}}

    def enviar_peticiones_selenium_upload(self):
        '''
            envia las peticiones con el archivo payload upload en los parametros
            
            como no se pueden obtener los inputs de forma predeterminada se obtienen durante el proceso
            por cada peticion que se realiza se obtienen los inputs de un form para luego ser validados
            cargados y enviados

            en este caso el input de tipo file se carga una ruta
        '''
        print("UPLOAD")
        json_formularios_selenium = {"forms_upload":{}}
        nombre_temporal = "_temp_"
        self.driver_upload.get(self.url)

        self.cargar_cookies_selenium(self.driver_upload)

        self.driver_upload.get(self.url)
        forms_totales = len(self.driver_upload.find_elements_by_xpath("//form"))
        contador = 0

        for form in range(forms_totales):
            existe_archivo = 0
            for archivo in self.lista_archivos:
                inputs_generales = []
                
                self.cargar_cookies_selenium(self.driver_upload)

                forms, inputs, textareas = forms, inputs, textareas = self.obtener_etiquetas_selenium(self.driver_upload, form)

                nombre_form = forms[form].get_attribute("name")
                id_form = forms[form].get_attribute("id")
                nombre_temporal_unico = "{0}_{1}_{2}".format("form",nombre_temporal,contador)
                nombre_form = self.obtener_nombre_etiqueta(nombre_form, id_form, nombre_temporal_unico)

                for input_unico in inputs:
                    nombre = input_unico.get_attribute("name")
                    id_input = input_unico.get_attribute("id")
                    tipo_input = input_unico.get_attribute("type")
                    tamanio_input = input_unico.size

                    if tipo_input == "file":
                        existe_archivo = 1
                        nombre_temporal_unico = "{0}_{1}_{2}".format("input",nombre_temporal,contador)
                        nombre_input = self.obtener_nombre_etiqueta(nombre, id_input, nombre_temporal_unico, tipo_input)
                        inputs_generales.append("{0} : {1}".format(nombre_input, archivo))
                        input_unico.send_keys(archivo)

                    elif self.validaciones.validar_tipo_input(tipo_input) and self.validaciones.validar_tamanio_input_selenium(tamanio_input) and tipo_input != "hidden":
                        nombre_temporal_unico = "{0}_{1}_{2}".format("input",nombre_temporal,contador)
                        nombre_input = self.obtener_nombre_etiqueta(nombre, id_input, nombre_temporal_unico, tipo_input)
                        if tipo_input.lower() != "submit":
                            input_unico.send_keys(self.cadena_aleatoria())

                for text_area in textareas:
                    text_area.send_keys(self.cadena_aleatoria())
                
                self.enviar_peticion_selenium(inputs)
                
                if existe_archivo == 0:
                    break

                upload = self.validaciones.validar_upload(self.driver_upload)
                upload_error = self.validaciones.validar_upload_error(self.driver_upload)

                if nombre_form not in json_formularios_selenium["forms_upload"]:
                    json_formularios_selenium["forms_upload"][nombre_form] = [{
                        "inputs":inputs_generales,
                        "upload":upload,
                        "posible_vulnerabilidad_comun":upload_error
                    }]

                else:
                    json_formularios_selenium["forms_upload"][nombre_form].append({
                        "inputs":inputs_generales,
                        "upload":upload,
                        "posible_vulnerabilidad_comun":upload_error
                    })
            contador += 1
                
        return json_formularios_selenium

    def enviar_peticiones_selenium_xss(self):
        '''
            envia las peticiones con el payload xss en los parametros

            como no se pueden obtener los inputs de forma predeterminada se obtienen durante el proceso
            por cada peticion que se realiza se obtienen los inputs de un form para luego ser validados
            cargados y enviados
        '''
        print("XSS SELENIUM")
        json_formularios_selenium = {"forms_selenium":{}}
        nombre_temporal = "_temp_"
        for i in range(3):
            try:
                self.driver_xss.get(self.url)

                self.cargar_cookies_selenium(self.driver_xss)

                self.driver_xss.get(self.url)
            except:
                if i == 2:
                    return json_formularios_selenium

        forms_totales = len(self.driver_xss.find_elements_by_xpath("//form"))
        contador = 0

        for form in range(forms_totales):
            for payload in self.payload_lista_xss:
                inputs_generales = []

                self.cargar_cookies_selenium(self.driver_xss)

                forms, inputs, textareas = forms, inputs, textareas = self.obtener_etiquetas_selenium(self.driver_xss, form)
                if forms != None:

                    nombre_form = forms[form].get_attribute("name")
                    id_form = forms[form].get_attribute("id")
                    nombre_temporal_unico = "{0}_{1}_{2}".format("form",nombre_temporal,contador)
                    nombre_form = self.obtener_nombre_etiqueta(nombre_form, id_form, nombre_temporal_unico)

                    for input_unico in inputs:
                        nombre = input_unico.get_attribute("name")
                        id_input = input_unico.get_attribute("id")
                        tipo_input = input_unico.get_attribute("type")
                        tamanio_input = input_unico.size

                        if self.validaciones.validar_tipo_input(tipo_input) and self.validaciones.validar_tamanio_input_selenium(tamanio_input) and tipo_input != "hidden":
                            nombre_temporal_unico = "{0}_{1}_{2}".format("input",nombre_temporal,contador)
                            nombre_input = self.obtener_nombre_etiqueta(nombre, id_input, nombre_temporal_unico, tipo_input)

                            if tipo_input.lower() != "submit":
                                inputs_generales.append("{0} : {1}".format(nombre_input, payload))
                                input_unico.send_keys(payload)

                    for text_area in textareas:
                        nombre = text_area.get_attribute("name")
                        id_text_area = text_area.get_attribute("id")
                        nombre_temporal_unico = "{0}_{1}_{2}".format("input",nombre_temporal,contador)
                        nombre_text_area = self.obtener_nombre_etiqueta(nombre, id_text_area, nombre_temporal_unico)
                        inputs_generales.append("{0} : {1}".format(nombre_text_area, payload))
                        text_area.send_keys(payload)


                    self.enviar_peticion_selenium(inputs)

                    if len(inputs_generales) == 0:
                        break

                    xss = self.validaciones.validar_xss_selenium(self.driver_xss)
                    posible = self.validaciones.validar_errores_comunes_selenium(self.driver_xss)                

                    if nombre_form not in json_formularios_selenium["forms_selenium"]:
                        json_formularios_selenium["forms_selenium"][nombre_form] = [{
                            "inputs":inputs_generales,
                            "xss":xss,
                            "posible_vulnerabilidad_comun":posible
                        }]

                    else:
                        json_formularios_selenium["forms_selenium"][nombre_form].append({
                            "inputs":inputs_generales,
                            "xss":xss,
                            "posible_vulnerabilidad_comun":posible
                        })

            contador += 1
        return json_formularios_selenium

    def set_opciones_selenium(self):
        '''
            configura las opciones del webdriver

            sin abrir el navegador
            modo root
            ignorando ssl autofirmados
        '''
        self.sin_navegador = webdriver.ChromeOptions()
        self.sin_navegador.add_argument('headless')      
        self.sin_navegador.add_argument('--no-sandbox')
        self.sin_navegador.add_argument('--disable-dev-shm-usage')
        self.sin_navegador.add_argument('--ignore-ssl-errors=yes')
        self.sin_navegador.add_argument('--ignore-certificate-errors')


    def set_peticion(self, json_temporal, carga, form, metodo):
        '''
            crea el esquema de la peticion por formulario para ser guardada dentro del json

            itera sobre la carga para cortarla por cada input

            Parametros
            ----------
            json_temporal : dict
            carga : dict
            form : int
            metodo : str
        '''
        if metodo == "get":
            inputs = [valor for valor in carga.split("&")]

        elif metodo == "post":
            inputs = ["{0}={1}".format(valor, carga[valor]) for valor in carga]
            
        json_temporal["forms"][form].append(
            {
                "inputs":inputs,
                "sqli":False,
                "xss":False,
                "sqli_blind":False,
                "sqli_blind_time":False,
                "posible_vulnerabilidad_comun":False,
                "posible_vulnerabilidad_xss":False,
                "codigo":0,
            }
        )
        return json_temporal

    def set_peticion_lfi(self, json_temporal, url, carga, metodo):
        '''
            crea el esquema de la peticion por pagina para ser guardada dentro del json

            itera sobre la carga para cortarla por cada input

            Parametros
            ----------
            json_temporal : dict
            carga : dict
            url : str
            metodo : str
        '''
        if metodo == "get":
            inputs = [url]

        elif metodo == "post":
            inputs = ["{0}={1}".format(valor, carga[valor]) for valor in carga]
            
        json_temporal["vulnerabilidades"]["lfi"].append(
            {
                "inputs":inputs,
                "lfi":False,
                "posible_vulnerabilidad":False,
                "codigo":0
            }
        )

    def set_formularios(self):
        '''
            obtiene todos los formularios
            
            realiza una peticion a la pagina para obtener todos los forms, inputs, textareas
            itera por cada form para obtener sus respectivos inputs y textareas cuales serán 
            almacenados dentro los formularios
        '''
        resultado = self.enviar_peticion_get(self.url)
        # resultado = self.sesion.get(self.url,cookies=self.cookies_requests,headers=self.headers,verify=False)
        if resultado is not None:
            html_proc = BeautifulSoup(resultado.text, "html.parser")
            self.formularios = {}
            forms = html_proc.find_all("form")
            nombre_temporal = "_temp_"
            bandera = 0
            for form_unico in forms:
                inputs_generales = []
                contador = 0

                nombre = form_unico.get("name")
                id_form = form_unico.get("id")
                nombre_temporal_unico = "{0}_{1}_{2}".format("form",nombre_temporal,contador)
                nombre_form = self.obtener_nombre_etiqueta(nombre, id_form, nombre_temporal_unico)
                contador += 1

                inputs = form_unico.find_all("input")
                for input_unico in inputs:
                    nombre = input_unico.get("name")
                    id_input = input_unico.get("id")
                    tipo_input = input_unico.get("type")
                    tamanio_input = input_unico.get("size")

                    if self.validaciones.validar_tipo_input(tipo_input) or (self.validaciones.validar_tamanio_input(tamanio_input) and tipo_input != "hidden"):
                        nombre_temporal_unico = "{0}_{1}_{2}".format("input",nombre_temporal,contador)
                        nombre_input = self.obtener_nombre_etiqueta(nombre, id_input, nombre_temporal_unico, tipo_input)
                        if nombre_input is not None:
                            inputs_generales.append(nombre_input)
                        contador += 1

                text_areas = form_unico.find_all("textarea")

                for text_area_unico in text_areas:
                    nombre = text_area_unico.get("name")
                    id_text_area = text_area_unico.get("id")
                    nombre_temporal_unico = "{0}_{1}_{2}".format("input",nombre_temporal,contador)
                    nombre_form = self.obtener_nombre_etiqueta(nombre, id_text_area, nombre_temporal_unico)
                    inputs_generales.append(nombre_form)
                    contador += 1

                metodo = form_unico.get("method")
                accion = urljoin(self.url,form_unico.get("action"))
                
                if metodo != None and metodo != "" and accion != None and accion != "" and accion.startswith("http") != False:
                    self.formularios[nombre_form] = {
                        "accion":accion,
                        "metodo":metodo.lower(),
                        "inputs":inputs_generales
                    }
                    self.json_fuzzing["forms"][nombre_form] = []
                    bandera = 1
            

            if urlparse(self.url).query != "" and bandera == 0:
                inputs_generales = []
                query = urlparse(self.url).query

                for valor in query.split("&"):
                    inputs_generales.append(valor.split("=")[0])

                self.url = self.url.replace(query, "")
                self.url = self.url[:-1]  
                self.formularios["form_especial"] = {
                    "accion":self.url,
                    "metodo":"get",
                    "inputs":inputs_generales
                }
                self.json_fuzzing["forms"]["form_especial"] = []
                
        self.json_fuzzing["vulnerabilidades"] = {"lfi":[]}
        self.json_fuzzing["forms_upload"] = {}
        self.json_fuzzing["forms_selenium"] = {}            

    def set_headers(self):
        '''
            crea los headers necesarios
        '''
        self.headers = {
            "User-Agent":self.user_agent.chrome
        }

    def get_formularios(self):
        '''
            obtiene los formularios
        '''
        return self.formularios

    def get_json_fuzzing(self):
        '''
            obtiene el json de la informacion procesada

        '''
        return self.json_fuzzing

    def execute(self):
        '''
            lanza el fuzzing 

            crea un hilo y este ejecuta el proceso del fuzzing
            guarda todo el proceso dentro del json_fuzzing

            ....
            Nota
            ----
            tiene la posibilidad de crear hilos para acelerar el procesamiento de los ataques

        '''
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            futures = [
                executor.submit(self.peticiones_xss),
                executor.submit(self.peticiones_sqli),
                executor.submit(self.peticiones_sqli_blind),
                executor.submit(self.peticiones_sqli_blind_time),
                executor.submit(self.peticiones_lfi),
                executor.submit(self.peticiones_selenium_xss),
                executor.submit(self.peticiones_selenium_upload)
            ]

            for future in concurrent.futures.as_completed(futures):
                json_future = future.result()

                if "forms" in json_future:
                    for form in json_future["forms"]:
                        self.json_fuzzing["forms"][form].extend(json_future["forms"][form])


                elif "forms_selenium" in json_future:
                    for form in json_future["forms_selenium"]:
                        self.json_fuzzing["forms_selenium"] = json_future["forms_selenium"]

                elif "forms_upload" in json_future:
                    for form in json_future["forms_upload"]:
                        self.json_fuzzing["forms_upload"] = json_future["forms_upload"]

                elif "vulnerabilidades" in json_future:
                    self.json_fuzzing["vulnerabilidades"]["lfi"].extend(
                        json_future["vulnerabilidades"]["lfi"])

def execute(parametros):
    '''
        regresa el resultado de lanzar un fuzzing completo a una pagina
    '''
    pagina = Pagina(parametros)
    pagina.execute()
    return pagina.get_json_fuzzing()
