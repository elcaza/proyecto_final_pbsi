from selenium import webdriver
from selenium.common.exceptions import NoAlertPresentException, UnexpectedAlertPresentException, NoSuchElementException, TimeoutException, ElementNotInteractableException, WebDriverException, JavascriptException, InvalidCookieDomainException
import time
import threading
import re
import requests
import urllib.parse
from modules import strings
import json

class SingletonMeta(type):
   _instances = {}
   def __call__(cls, *args, **kwargs):
      if cls not in cls._instances:
         instance = super().__call__(*args, **kwargs)
         cls._instances[cls] = instance
      return cls._instances[cls]

class Singleton_Diccionarios_ataque(metaclass=SingletonMeta):
   def __init__(self, diccionario_xss, diccionario_sqli, diccionario_lfi):
      self.set_xss(diccionario_xss)
      self.set_sqli(diccionario_sqli)
      self.set_lfi(diccionario_lfi)
      self.diccionarios = {"xss":self.diccionario_xss, "sqli":self.diccionario_sqli, "lfi":self.diccionario_lfi}
      self.cantidad_diccionarios = len(self.diccionarios)

   def set_xss(self,diccionario_xss):
      try:
         with open(diccionario_xss,"r") as xss:
            self.diccionario_xss = xss.read().split("\n")
      except FileNotFoundError:
         self.diccionario_xss = [""]

   def set_sqli(self,diccionario_sqli):
      try:
         with open(diccionario_sqli,"r") as sqli:
            self.diccionario_sqli = sqli.read().split("\n")
      except FileNotFoundError:
         self.diccionario_sqli= [""]

   def set_lfi(self,diccionario_lfi):
      try:
         with open(diccionario_lfi,"r") as lfi:
            self.diccionario_lfi = lfi.read().split("\n")
      except FileNotFoundError:
         self.diccionario_lfi = [""]

   def get_xss(self):
      return self.diccionario_xss

   def get_sqli(self):
      return self.diccionario_sqli

   def get_lfi(self):
      return self.diccionario_lfi

   def get_diccionario(self, diccionario):
      return self.diccionarios[diccionario]
   
   def get_diccionarios(self):
      return self.diccionarios

   def get_diccionario_tipo(self, numero_diccionario):
      return True

class Singleton_Diccionarios_validacion(metaclass=SingletonMeta):
   def __init__(self, diccionario_validar_sqli, diccionario_validar_lfi, manejador = "", sistema = ""):
      self.manejador = manejador
      self.sistema = sistema
      self.patron = r"[[a-zA-Z0-9]+]"
      self.set_validar_sqli(diccionario_validar_sqli)
      self.set_validar_lfi(diccionario_validar_lfi)
      
   def set_validar_sqli(self,diccionario_validar_sqli):
      try:
         with open(diccionario_validar_sqli,"r") as sqli:
            self.diccionario_validar_sqli = sqli.read().split("\n")
         bandera = 0
         diccionario_temporal = ""
         if self.manejador != "":
            for cadena in self.diccionario_validar_sqli:
               existe_manejador = re.search(self.manejador,cadena)
               existe_otro_manejador = re.search(self.patron,cadena)
               if bandera == 1 and existe_otro_manejador is not None:
                  bandera = 0
               elif bandera == 1:
                  diccionario_temporal += cadena + "\n"
               elif existe_manejador is not None:
                  bandera = 1
            
         else:
            for cadena in self.diccionario_validar_sqli:
               existe_manejador = re.search(self.patron,cadena)
               if existe_manejador is None:
                  diccionario_temporal += cadena + "\n"
         
         self.diccionario_validar_sqli = diccionario_temporal.split("\n")[:-1]

      except FileNotFoundError:
         self.diccionario_validar_sqli = [""]

   def set_validar_lfi(self,diccionario_validar_lfi):
      try:
         with open(diccionario_validar_lfi,"r") as lfi:
            self.diccionario_validar_lfi = lfi.read().split("\n")

         bandera = 0
         diccionario_temporal = ""
         if self.sistema != "":
            for cadena in self.diccionario_validar_lfi:
               existe_sistema = re.search(self.sistema,cadena)
               existe_otro_sistema = re.search(self.patron,cadena)
               if bandera == 1 and existe_otro_sistema is not None:
                  bandera = 0
               elif bandera == 1:
                  diccionario_temporal += cadena + "\n"
               elif existe_sistema is not None:
                  bandera = 1
         
         else:
            for cadena in self.diccionario_validar_lfi:
               existe_sistema = re.search(self.patron,cadena)
               if existe_sistema is None:
                  diccionario_temporal += cadena + "\n"
         
         self.diccionario_validar_lfi = diccionario_temporal.split("\n")[:-1]
      except FileNotFoundError:
         self.diccionario_validar_lfi = [""]

   def get_validar_sqli(self):
      return self.diccionario_validar_sqli

   def get_validar_lfi(self):
      return self.diccionario_validar_lfi

class Lanzar_fuzzing(threading.Thread):
   def __init__(self, threadID, nombre, diccionario, url, tipo, cookie):
      threading.Thread.__init__(self)
      self.sin_navegador = webdriver.ChromeOptions()
      self.sin_navegador.add_argument('headless')      
      self.sin_navegador.add_argument('--no-sandbox')
      self.sin_navegador.add_argument('--disable-dev-shm-usage')
      #WebDriverException
      try: 
         self.driver = webdriver.Chrome("/usr/bin/chromedriver",options=self.sin_navegador)
         self.driver.set_page_load_timeout(5)
         self.error = 0
      except WebDriverException:
         self.error = 1
      #self.driver = webdriver.Chrome("/usr/bin/chromedriver")
      self.threadID = threadID
      self.nombre = nombre
      self.diccionario = diccionario
      self.url = url
      self.tipo = tipo
      self.cookie = cookie
      self.json_fuzzing_forms = {"forms":{}}
      self.json_forms = {"forms":{}}

   def run(self):
      if self.error == 0:
         print("Pagina - " + self.url)
         print ("[+1] Hilo Selenium - " + self.nombre)
         enviar_peticiones(self.driver, self.url, self.diccionario, self.tipo, self.json_fuzzing_forms, self.json_forms, self.cookie)
         self.driver.quit()
         print ("[+2] Hilo Request - " + self.nombre)
         pre_enviar_peticiones(self.json_forms, self.diccionario, self.tipo, self.json_fuzzing_forms, self.cookie)
         print ("[-] Hilo - " + self.nombre)
      
   def reiniciar_driver(self):
      self.sin_navegador = webdriver.ChromeOptions()
      self.sin_navegador.add_argument('headless')
      self.driver = webdriver.Chrome(options=self.sin_navegador)

   def get_driver(self):
      return self.driver
   
   def get_json_fuzzing_forms(self):
      return self.json_fuzzing_forms
      
   def get_forms(self):
      self.json_fuzzing_forms

class Form():
   def __init__(self, driver_form):
      self.form = driver_form
      self.id = self.get_id()
      self.nombre = self.get_nombre()
      self.metodo = self.get_metodo()
      self.accion = self.get_accion()
      self.inputs = self.get_inputs()
      self.selects = self.get_selects()
      self.buttons = self.get_buttons()
      self.form_completo = self.get_form()
      self.peticion = ""

   def get_inputs(self):
      return self.form.find_elements_by_xpath(".//input")

   def get_selects(self):
      return self.form.find_elements_by_xpath(".//select")

   def get_buttons(self):
      return self.form.find_elements_by_xpath(".//button")

   def get_metodo(self):
      return self.form.get_attribute("method")

   def get_nombre(self):
      return self.form.get_attribute("name")

   def get_accion(self):
      return self.form.get_attribute("action")

   def get_id(self):
      return self.form.get_attribute("id")

   def get_form(self):
      lista_forms = {}
      lista_inputs = []
      lista_inputs_nombre = []

      for entrada in self.inputs:
         if entrada.get_attribute("type") == "text" or entrada.get_attribute("type") == "password":
            if entrada.size["height"] != 0 and entrada.size["width"] != 0: 
               lista_inputs.append(entrada)
               lista_inputs_nombre.append(entrada.get_attribute("id") if entrada.get_attribute("id") != "" else entrada.get_attribute("name"))
      lista_forms["form"] = {
         "inputs":lista_inputs,
         "inputs_nombres":lista_inputs_nombre,
         "selects":self.selects,
         "nombre":self.nombre,
         "metodo":self.metodo,
         "accion":self.accion
      }
      return lista_forms

   def enviar_peticion(self):
      self.peticion = ""
      for valor in self.form_completo["form"]["inputs"]:
         self.peticion += "Input:"+valor.get_attribute("id")+" Valor:"+valor.get_attribute("value")+" "
      try:
         self.form.submit()
         return False
      except TimeoutException:
         return True
      except JavascriptException:
         for valor in self.form_completo["form"]["inputs"]:
            if valor.get_attribute("name").lower() == "submit" or valor.get_attribute("id").lower() == "submit":
               valor.click()

   def set_input(self, input_individual, valor):
      try:
         self.form_completo["form"]["inputs"][input_individual].send_keys(valor)
      except ElementNotInteractableException:
         pass
      
   def get_lista_inputs(self):
      return self.form_completo["form"]["inputs"]
   
   def get_form_completo(self):
      return self.form_completo

   def get_peticion(self):
      return self.peticion

def actualizar_profundidad_iframes(driver, iframe_profundidad, iframe_posicion):

   if iframe_posicion > -1:
      for profundidad in range(iframe_profundidad):
         # Try
         try:
            driver.switch_to.frame(driver.find_elements_by_tag_name("iframe")[iframe_posicion])
         except TimeoutException:
            pass
   return True

def actualizar_formulario(driver,formulario_iteracion, url, iframe_posicion = -1, iframe_profundidad = 0, error = 0):
   try:
      driver.get(url)
      actualizar_profundidad_iframes(driver, iframe_profundidad, iframe_posicion)
      #Index Out
      formulario = Form(driver.find_elements_by_xpath(".//form")[formulario_iteracion])
      inputs = formulario.get_lista_inputs()
      return formulario, inputs
   except UnexpectedAlertPresentException:
      return actualizar_formulario(driver,formulario_iteracion,url,iframe_posicion, iframe_profundidad, error)
   except TimeoutException:
      if error < 5:
         error += 1
         return actualizar_formulario(driver,formulario_iteracion,url, iframe_posicion, iframe_profundidad, error)
      else:
         return False, False

def enviar_peticiones(driver, url, diccionario, tipo, json_fuzzing, json_forms, cookie=[], iframe_posicion = -1, iframe_profundidad = 0, error = 0):

   if iframe_posicion == -1:
      # Falla en Tiempo de ejecucion
      while True:
         try:
            driver.get(url)   
            error = 0
            break
         except TimeoutException:
            if error < 5:
               error += 1
            else:
               error = 0
               break

      if len(cookie) > 0:
         for cookie_individual in cookie:
            try:
               driver.add_cookie(cookie_individual)
            except InvalidCookieDomainException:
               print("Cookie invalida")
               pass
   # Encuentros de iFrame embebidos
   try:
      actualizar_profundidad_iframes(driver, iframe_profundidad, iframe_posicion)
      iframes = len(driver.find_elements_by_tag_name("iframe"))
      if iframes != 0:
         for iframe in range(iframes):
            iframe_profundidad += 1
            
            enviar_peticiones(driver, url, diccionario, tipo, json_fuzzing, json_forms, cookie, iframe, iframe_profundidad, error)
            driver.get(url)
            time.sleep(0.5)
            iframe_profundidad -= 1
            actualizar_profundidad_iframes(driver, iframe_profundidad, iframe_posicion)

   except NoSuchElementException:
      iframe_posicion = -1

   cantidad_formularios = driver.find_elements_by_xpath(".//form")
   
   for formulario_iteracion in range(len(cantidad_formularios)):
      for valor in diccionario:
         formulario, inputs = actualizar_formulario(driver,formulario_iteracion, url, iframe_posicion, iframe_profundidad)
         if formulario == False:
            return False
         for input_individual in range(len(inputs)):
            formulario.set_input(input_individual,valor)
         form_nombre = formulario.get_nombre()
         form_id = formulario.get_id()
         form_utilizar = ""

         if form_id == "":
            if form_nombre == "":
               form_utilizar = "form {0}-{1}".format(iframe_profundidad,iframe_posicion)
            else:
               form_utilizar = form_nombre
         else:
            form_utilizar = form_id

         form_completo = formulario.get_form_completo()
         
         if json_forms["forms"].get(form_utilizar) is None:
            json_forms["forms"].update({form_utilizar:{}})
            json_forms["forms"][form_utilizar]["metodo"] = form_completo["form"]["metodo"]
            json_forms["forms"][form_utilizar]["accion"] = form_completo["form"]["accion"]
            json_forms["forms"][form_utilizar]["inputs"] = form_completo["form"]["inputs_nombres"]

         vulnerabilidad_tiempo = formulario.enviar_peticion()

         if json_fuzzing["forms"].get(form_utilizar) is None:
            json_fuzzing["forms"].update({form_utilizar:[]})
         json_fuzzing["forms"][form_utilizar].append({"inputs":[],"tipo":tipo,"xss":False,"sqli":False,"lfi":False,"codigo":0})
         i = len(json_fuzzing["forms"][form_utilizar])-1
         json_fuzzing["forms"][form_utilizar][i]["inputs"] = formulario.get_peticion()

         if vulnerabilidad_tiempo:
            if tipo == "xss":
               json_fuzzing["forms"][form_utilizar][i]["xss"] = True
            elif tipo == "sqli":
               json_fuzzing["forms"][form_utilizar][i]["sqli"] = True
            elif tipo == "lfi":
               json_fuzzing["forms"][form_utilizar][i]["lfi"] = True
            continue

         time.sleep(0.1)
         json_fuzzing["forms"][form_utilizar][i]["xss"] = validarXSS(driver)
         json_fuzzing["forms"][form_utilizar][i]["sqli"] = validarSQLi(driver)
         json_fuzzing["forms"][form_utilizar][i]["lfi"] = validarLFI(driver)
         del formulario
   return True

def validarXSS(driver):
   try:
      alerta = driver.switch_to.alert
      if alerta.text is not None:
         alerta.accept()
         return True
   except NoAlertPresentException:
      return False

def validarSQLi(driver):
   diccionario = Singleton_Diccionarios_validacion()
   for cadena in diccionario.get_validar_sqli():
      existe = re.search(re.compile(re.escape(cadena)), driver.page_source)
      if existe is not None:
         return True
   del diccionario
   return False

def validarLFI(driver):
   diccionario = Singleton_Diccionarios_validacion()
   for cadena in diccionario.get_validar_lfi():
      existe = re.search(re.compile(re.escape(cadena)), driver.page_source)
      if existe is not None:
         return True
   del diccionario
   return False
   
def crear_hijos_fuzzing(url, cookie=[]):
   diccionarios = Singleton_Diccionarios_ataque()
   json_fuzzing = {"forms": {}}

   hijos = []
   hilo = 0
   hilos = 3

   subdiccionarios = diccionarios.get_diccionarios()
   for diccionario in subdiccionarios:
      hijos.append(Lanzar_fuzzing(hilo, "Fuzzing-{0}".format(diccionario), subdiccionarios[diccionario], url, diccionario, cookie))
      hilo += 1

   for hilo in range(hilos):
      hijos[hilo].start()
   for hilo in range(hilos):
      hijos[hilo].join()
   for hilo in range(hilos):
      forms = hijos[hilo].get_json_fuzzing_forms()
      if len(forms["forms"]) != 0:
         for form in forms["forms"]:
            if form in json_fuzzing["forms"]:
               json_fuzzing["forms"][form].extend(forms["forms"][form])
            else:
               json_fuzzing["forms"][form] = forms["forms"][form]

   del diccionarios
   return json_fuzzing
   
def obtener_valores_iniciales(parametros):
   url = parametros["url"]
   cookie = parametros["cookie"]
   Singleton_Diccionarios_ataque(strings.DICCIONARIO_ATAQUE_XSS,strings.DICCIONARIO_ATAQUE_SQLI,strings.DICCIONARIO_ATAQUE_LFI)
   Singleton_Diccionarios_validacion(strings.DICCIONARIO_VALIDACION_SQLI,strings.DICCIONARIO_VALIDACION_LFI)
   cookie = convertir_cookie(cookie)
   return url, cookie

def convertir_cookie(cookie):
   cookies_individuales = []
   if cookie == "":
      return cookies_individuales
   if cookie.__contains__(","):
      subcookies = cookie.split(",")
      for subcookie in subcookies:
         cookie_individual_temporal = subcookie.split(":")
         cookies_individuales.append({"name":cookie_individual_temporal[0],"value":cookie_individual_temporal[1]})
   else:
      cookie_individual_temporal = cookie.split(":")
      cookies_individuales.append({"name":cookie_individual_temporal[0],"value":cookie_individual_temporal[1]})
   return cookies_individuales

def pre_enviar_peticiones(forms, diccionario, tipo, json_fuzzing, cookie=[]):
   sesion = requests.session()
   headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"}
   cookies = {}
   if len(cookie) != 0:
      for subcookie in cookie:
         cookies[subcookie["name"]] = subcookie["value"]

   for form in forms["forms"]:
      url = forms["forms"][form]["accion"]
      if url.startswith("http"):
         metodo = forms["forms"][form]["metodo"]
         i = 0
         if metodo.lower() == "get":
            for valor in diccionario:
               payload = "?"
               for input_individual in forms["forms"][form]["inputs"]:
                  payload += input_individual+"="+valor
               
               peticion = sesion.get(url+payload, headers=headers, cookies=cookies)
               codigo = validarPreCodigo(peticion)

               if codigo:
                  if tipo == "xss":
                     json_fuzzing["forms"][form][i]["xss"] = True
                  elif tipo == "sqli":
                     json_fuzzing["forms"][form][i]["sqli"] = True
                  elif tipo == "lfi":
                     json_fuzzing["forms"][form][i]["lfi"] = True
                  
                  json_fuzzing["forms"][form][i]["codigo"] = codigo
                  continue

               if peticion.elapsed.seconds > 5:
                  if tipo == "xss":
                     json_fuzzing["forms"][form][i]["xss"] = True
                  elif tipo == "sqli":
                     json_fuzzing["forms"][form][i]["sqli"] = True
                  elif tipo == "lfi":
                     json_fuzzing["forms"][form][i]["lfi"] = True
                  continue
               
               if tipo == "xss":
                  payload_xss = urllib.parse.unquote(valor)
                  if json_fuzzing["forms"][form][i]["xss"] == False:
                     json_fuzzing["forms"][form][i]["xss"] = validarPreXSS(peticion, payload_xss)
               if json_fuzzing["forms"][form][i]["sqli"] == False:
                  json_fuzzing["forms"][form][i]["sqli"] = validarPreSQLi(peticion)
               if json_fuzzing["forms"][form][i]["lfi"] == False:
                  json_fuzzing["forms"][form][i]["lfi"] = validarPreLFI(peticion)
               i += 1
               
         if metodo.lower() == "post":
            for valor in diccionario:
               payload = {}
               for input_individual in forms["forms"][form]["inputs"]:
                  payload[input_individual] = valor

               peticion = sesion.post(url, headers=headers, cookies=cookies, data=json.dumps(payload))
               codigo = validarPreCodigo(peticion)

               if codigo:
                  if tipo == "xss":
                     json_fuzzing["forms"][form][i]["xss"] = True
                  elif tipo == "sqli":
                     json_fuzzing["forms"][form][i]["sqli"] = True
                  elif tipo == "lfi":
                     json_fuzzing["forms"][form][i]["lfi"] = True
                     
                  json_fuzzing["forms"][form][i]["codigo"] = codigo
                  continue

               if peticion.elapsed.seconds > 5:
                  if tipo == "xss":
                     json_fuzzing["forms"][form][i]["xss"] = True
                  elif tipo == "sqli":
                     json_fuzzing["forms"][form][i]["sqli"] = True
                  elif tipo == "lfi":
                     json_fuzzing["forms"][form][i]["lfi"] = True
                  continue
               
               if tipo == "xss":
                  payload_xss = urllib.parse.unquote(valor)
                  if json_fuzzing["forms"][form][i]["xss"] == False:
                     json_fuzzing["forms"][form][i]["xss"] = validarPreXSS(peticion, payload_xss)
               # Index out
               if json_fuzzing["forms"][form][i]["sqli"] == False:
                  json_fuzzing["forms"][form][i]["sqli"] = validarPreSQLi(peticion)
               if json_fuzzing["forms"][form][i]["lfi"] == False:
                  json_fuzzing["forms"][form][i]["lfi"] = validarPreLFI(peticion)
               i += 1
 
def validarPreXSS(peticion, payload):
   existe = re.search(re.compile(re.escape(payload)), peticion.content.decode("ISO-8859-1"))

   if existe is not None:
      return True
   return False

def validarPreSQLi(peticion):
   diccionario = Singleton_Diccionarios_validacion()
   for cadena in diccionario.get_validar_sqli():
      existe = re.search(re.compile(re.escape(cadena)), peticion.content.decode("ISO-8859-1"))
      if existe is not None:
         return True
   del diccionario
   return False

def validarPreLFI(peticion):
   diccionario = Singleton_Diccionarios_validacion()
   for cadena in diccionario.get_validar_lfi():
      existe = re.search(re.compile(re.escape(cadena)), peticion.content.decode("ISO-8859-1"))
      if existe is not None:
         return True
   del diccionario
   return False
   
def validarPreCodigo(peticion):
   codigo = peticion.status_code
   if codigo >= 500 or codigo <= 599:
      return True

def execute(parametros):
   url, cookie = obtener_valores_iniciales(parametros)
   json_fuzzing = crear_hijos_fuzzing(url,cookie)
   return json_fuzzing

'''

'''