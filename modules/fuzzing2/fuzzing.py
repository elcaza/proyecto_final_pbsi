import re, requests, json
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from fake_useragent import UserAgent
from os import path
import concurrent.futures
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class Validaciones():
    def __init__(self):
        self.ruta = path.abspath(path.dirname(__file__))

    def validar_tipo_input(self, tipo):
        if tipo == "text" or tipo == "password" or tipo == "submit" or tipo == None:
            return True
        return False

    def validar_tamanio_input(self, tamanio):
        if tamanio:
            try:
                tamanio = int(tamanio)
                if tamanio > 0:
                    return True
            except:
                return False
        return False

    def validar_xss(self, resultado, payload):
        texto = resultado.text
        payload = re.escape(payload)
        resultado = re.search(payload,texto)
        if resultado:
            return True
        return False

    def validar_sqli(self, resultado, payload):
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
        tiempo = resultado.elapsed.seconds
        if tiempo >= 10:
            return True
        return False
        
    def validar_sqli_blind(self, resultado_correcto,resultado_incorrecto,resultado_payload,payload):
        texto_correcto = resultado_correcto.text
        texto_incorrecto = resultado_incorrecto.text
        texto_payload = resultado_payload.text
        if texto_payload == texto_correcto and texto_correcto != texto_incorrecto:
            return True
        return False

    def validar_lfi(self, resultado):
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
        codigo = resultado.status_code
        if codigo >= 500 and codigo <=599:
            return codigo,True
        return codigo,False

    def validar_errores_comunes(self, resultado):
        try:
            ruta = "{0}{1}".format(self.ruta,"/validacion_errores_comunes.json")
            with open(ruta,"r") as errores:
                self.errores_comunes = json.load(errores)
        except FileNotFoundError:
            self.errores_comunes = []

        texto = resultado.text
        for error in self.errores_comunes:
            if re.search(re.escape(error),texto):
                print("SQLi",error)
                return True
        return False

    def validar_error_lfi(self, resultado):
        try:
            ruta = "{0}{1}".format(self.ruta,"/validacion_errores_lfi.json")
            with open(ruta,"r") as errores:
                self.errores_lfi = json.load(errores)
        except FileNotFoundError:
            self.errores_lfi = []

        texto = resultado.text
        for error in self.errores_lfi:
            if re.search(re.escape(error),texto):
                print("LFI",error)
                return True
        return False

class Pagina():
    def __init__(self, parametros):
        self.url = parametros["url"]
        self.sesion = requests.session()
        self.regex_patron = r"\{(.*)\}"
        self.user_agent = UserAgent()
        self.ruta = path.abspath(path.dirname(__file__))
        self.validaciones = Validaciones()
        self.json_fuzzing = {"forms":{}}
        self.convertir_cookie(parametros["cookie"])
        self.set_headers()
        self.set_formularios()
        self.combinaciones_xss()
        self.combinaciones_lfi()
        self.combinaciones_sqli()
        self.combinaciones_sqli_blind()
        self.combinaciones_sqli_blind_time()
        
    def enviar_validacion_comun(self, resultado, json_temporal={}, form={}, posicion=0, lfi=False):
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
                    resultado = self.sesion.get(url_cargada,cookies=self.cookies_requests,headers=self.headers,verify=False)

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
                    resultado = self.sesion.post(url_cargada,cookies=self.cookies_requests,data=data,verify=False)

                    if funcion_validadora(resultado, payload):
                        json_temporal["forms"][form_unico][i][tipo] = True
                    
                    self.enviar_validacion_comun(resultado, json_temporal, form_unico, i)
                    i += 1
        return json_temporal

    def obtener_nombre_etiqueta(self, nombre_etiqueta, id_etiqueta, nombre_temporal, tipo = ""):
        if tipo == "submit" and (id_etiqueta == None or id_etiqueta == "") and (nombre_etiqueta == None or nombre_etiqueta == ""):
            return "submit"
        if id_etiqueta == None or id_etiqueta == "":
            if nombre_etiqueta == None or nombre_etiqueta == "":
                return nombre_temporal
            else:
                return nombre_etiqueta
        else:
            return id_etiqueta

    def convertir_cookie(self, cookie):
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
        try:
            ruta = "{0}{1}".format(self.ruta,"/xss.json")
            with open(ruta,"r") as xss:
                self.payload_lista_xss = json.load(xss)
        except FileNotFoundError:
            self.payload_lista_xss = []

    def combinaciones_lfi(self):
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
        try:
            ruta = "{0}{1}".format(self.ruta,"/sqli_blind.json")
            with open(ruta,"r") as sqli_blind:
                self.payload_lista_sqli_blind = json.load(sqli_blind)
        except FileNotFoundError:
            self.peticiones_sqli_blind = []

    def combinaciones_sqli_blind_time(self):
        try:
            ruta = "{0}{1}".format(self.ruta,"/sqli_blind_time.json")
            with open(ruta,"r") as sqli_blind_time:
                self.payload_lista_sqli_blind_time = json.load(sqli_blind_time)
        except FileNotFoundError:
            self.payload_lista_sqli_blind_time = []

    def peticiones_xss(self):
        print("XSS")
        json_temporal = self.enviar_peticiones_xss_sqli_sqliT(self.payload_lista_xss,self.validaciones.validar_xss,"xss")
        return json_temporal

    def peticiones_sqli(self):
        print("SQLi")
        json_temporal = self.enviar_peticiones_xss_sqli_sqliT(self.payload_lista_sqli,self.validaciones.validar_sqli,"sqli")
        return json_temporal

    def peticiones_sqli_blind(self):
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
                    resultado_correcto = self.sesion.get(url_cargada,cookies=self.cookies_requests,headers=self.headers,verify=False)
                    url_cargada = "{0}?{1}".format(self.formularios[form_unico]["accion"],carga_incorrecta)
                    resultado_incorrecto = self.sesion.get(url_cargada,cookies=self.cookies_requests,headers=self.headers,verify=False)
                    url_cargada = "{0}?{1}".format(self.formularios[form_unico]["accion"],carga_payload)
                    resultado_payload = self.sesion.get(url_cargada,cookies=self.cookies_requests,headers=self.headers,verify=False)

                    self.set_peticion(json_temporal, "[{0}{1}] = {2}".format(carga_correcta,carga_incorrecta,carga_payload),form_unico,metodo)
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
                            data_correcta[input_unico] = payload["correcto"]
                            data_incorrecta[input_unico] = payload["incorrecto"]
                            data_payload[input_unico] = payload["payload"]
                    if bandera_submit != "":
                        data_correcta[bandera_submit] = "Submit"
                        data_incorrecta[bandera_submit] = "Submit"
                        data_payload[bandera_submit] = "Submit"

                    url_cargada = self.formularios[form_unico]["accion"]
                    resultado_correcto = self.sesion.post(url_cargada,cookies=self.cookies_requests,data=data_correcta,verify=False)
                    resultado_incorrecto = self.sesion.post(url_cargada,cookies=self.cookies_requests,data=data_incorrecta,verify=False)
                    resultado_payload = self.sesion.post(url_cargada,cookies=self.cookies_requests,data=data_payload,verify=False)
                    self.set_peticion(json_temporal, data_correcta | data_incorrecta | data_payload,form_unico,metodo)

                    if self.validaciones.validar_sqli_blind(resultado_correcto,resultado_incorrecto,resultado_payload, payload):
                        json_temporal["forms"][form_unico][i]["sqli_blind"] = True

                    self.enviar_validacion_comun(resultado_correcto, json_temporal,form_unico, i)
                    self.enviar_validacion_comun(resultado_incorrecto, json_temporal,form_unico, i)
                    self.enviar_validacion_comun(resultado_payload, json_temporal,form_unico, i)

                    i += 1
        return json_temporal

    def peticiones_sqli_blind_time(self):
        print("SQLi Blind Time")
        json_temporal = self.enviar_peticiones_xss_sqli_sqliT(self.payload_lista_sqli_blind_time,self.validaciones.validar_sqli_blind_time,"sqli_blind_time")
        return json_temporal

    def peticiones_lfi(self):
        print("LFI")
        json_temporal = {"vulnerabilidades":{"lfi":[]}}
        regex_sin_archivo = r".*\?\w+="
        archivo = re.search(regex_sin_archivo,self.url)
        i = 0
        if archivo:
            for payload in self.payload_lista_lfi:
                url_cargada = "{0}{1}".format(archivo.group(),payload)
                self.set_peticion_lfi(json_temporal, url_cargada, payload, "get")
                resultado = self.sesion.get(url_cargada,cookies=self.cookies_requests,headers=self.headers,verify=False)

                if self.validaciones.validar_lfi(resultado):
                    json_temporal["vulnerabilidades"]["lfi"][i]["lfi"] = True
                    
                self.enviar_validacion_comun(resultado,json_temporal,posicion=i,lfi=True)
                i += 1
                
        else:
            for tipo in self.payload_lista_lfi_tipos:
                for payload in self.payload_lista_lfi:
                    url_cargada = "{0}?{1}={2}".format(self.url,tipo,payload)
                    self.set_peticion_lfi(json_temporal, url_cargada, payload,"get")
                    resultado = self.sesion.get(url_cargada,cookies=self.cookies_requests,headers=self.headers,verify=False)
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
                resultado = self.sesion.post(url_cargada,cookies=self.cookies_requests,data=data,headers=self.headers,verify=False)
                if self.validaciones.validar_lfi(resultado):
                    json_temporal["vulnerabilidades"]["lfi"][i]["lfi"] = True
                self.enviar_validacion_comun(resultado,json_temporal,posicion=i,lfi=True)
                i += 1
        return json_temporal
    
    def set_peticion(self, json_temporal, carga, form, metodo):
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
                "codigo":0,
            }
        )
        return json_temporal

    def set_peticion_lfi(self, json_temporal, url, carga, metodo):
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
        resultado = self.sesion.get(self.url,cookies=self.cookies_requests,headers=self.headers,verify=False)
        html_proc = BeautifulSoup(resultado.text, "html.parser")
        self.formularios = {}
        forms = html_proc.find_all("form")
        nombre_temporal = "_temp_"

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

                if self.validaciones.validar_tipo_input(tipo_input) or self.validaciones.validar_tamanio_input(tamanio_input):
                    nombre_temporal_unico = "{0}_{1}_{2}".format("input",nombre_temporal,contador)
                    nombre_input = self.obtener_nombre_etiqueta(nombre, id_input, nombre_temporal_unico, tipo_input)
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
        self.json_fuzzing["vulnerabilidades"] = {"lfi":[]}

    def set_headers(self):
        self.headers = {
            "User-Agent":self.user_agent.chrome
        }

    def get_formularios(self):
        return self.formularios

    def get_json_fuzzing(self):
        return self.json_fuzzing

    def execute(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [
                executor.submit(self.peticiones_xss),
                executor.submit(self.peticiones_sqli),
                executor.submit(self.peticiones_sqli_blind),
                executor.submit(self.peticiones_sqli_blind_time),
                executor.submit(self.peticiones_lfi)
            ]

            for future in concurrent.futures.as_completed(futures):
                json_future = future.result()

                if "forms" in json_future:
                    for form in json_future["forms"]:
                        self.json_fuzzing["forms"][form].extend(json_future["forms"][form])

                elif "vulnerabilidades" in json_future:
                    self.json_fuzzing["vulnerabilidades"]["lfi"].extend(
                        json_future["vulnerabilidades"]["lfi"])

def execute(parametros):
    pagina = Pagina(parametros)
    pagina.execute()
    return pagina.get_json_fuzzing()
