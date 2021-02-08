from selenium import webdriver
from selenium.common.exceptions import NoAlertPresentException, UnexpectedAlertPresentException, NoSuchElementException, TimeoutException
import time
import threading
import math
import re
from modules import strings

class SingletonMeta(type):
   _instances = {}
   def __call__(cls, *args, **kwargs):
      if cls not in cls._instances:
         instance = super().__call__(*args, **kwargs)
         cls._instances[cls] = instance
      return cls._instances[cls]

class Singleton_Banderas_formulario(metaclass=SingletonMeta):
   existe = None
   arreglo_bandera = None
   def set_banderas_formulario(self,arreglo_banderas):
      if self.existe is None:    
         self.banderas= arreglo_banderas

   def get_bandera(self,iteracion):
      return self.banderas[iteracion]

   def set_bandera(self,iteracion):
      self.banderas[iteracion] = 1

   def reiniciar_banderas_formulario(self):
      self.banderas = None
      self.existe = None

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
      self.driver = webdriver.Chrome("/usr/bin/chromedriver",options=self.sin_navegador)
      #self.driver = webdriver.Chrome()
      self.driver.set_page_load_timeout(5)
      self.threadID = threadID
      self.nombre = nombre
      self.diccionario = diccionario
      self.url = url
      self.tipo = tipo
      self.cookie = cookie
      self.json_fuzzing_forms = {"forms":{}}

   def run(self):
      print ("Starting " + self.nombre)
      enviar_peticiones(self.driver, self.url, self.diccionario, self.tipo, self.json_fuzzing_forms, self.cookie, -1)
      self.driver.quit()
      print ("Exiting " + self.nombre)

   def reiniciar_driver(self):
      self.sin_navegador = webdriver.ChromeOptions()
      self.sin_navegador.add_argument('headless')
      self.driver = webdriver.Chrome(options=self.sin_navegador)

   def get_driver(self):
      return self.driver
   
   def get_json_fuzzing_forms(self):
      return self.json_fuzzing_forms

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

      for entrada in self.inputs:
         if entrada.get_attribute("type") == "text" or entrada.get_attribute("type") == "password":
            lista_inputs.append(entrada)
      lista_forms["form"] = {
         "inputs":lista_inputs,
         "selects":self.selects,
         "nombre":self.nombre,
         "metodo":self.metodo,
         "accion":self.accion
      }
      return lista_forms

   def enviar_peticion(self):
      self.peticion = ""
      for valor in self.form_completo["form"]["inputs"]:
         self.peticion += valor.get_attribute("id")+":"+valor.get_attribute("value")+" "
      try:
         self.form.submit()
         return False
      except TimeoutException:
         return True

   def set_input(self, input_individual, valor):
      self.form_completo["form"]["inputs"][input_individual].send_keys(valor)
      
   def get_lista_inputs(self):
      return self.form_completo["form"]["inputs"]
   
   def get_peticion(self):
      return self.peticion

def actualizar_profundidad_iframes(driver, iframe_profundidad, iframe_posicion):

   if iframe_posicion > -1:
      for profundidad in range(iframe_profundidad):
         driver.switch_to.frame(driver.find_elements_by_tag_name("iframe")[iframe_posicion])
   return True

def actualizar_formulario(driver,formulario_iteracion, url, iframe_posicion = -1, iframe_profundidad = 0):
   try:
      driver.get(url)

      actualizar_profundidad_iframes(driver, iframe_profundidad, iframe_posicion)
   
      formulario = Form(driver.find_elements_by_xpath(".//form")[formulario_iteracion])
      inputs = formulario.get_lista_inputs()
      return formulario, inputs
   except (UnexpectedAlertPresentException,TimeoutException):
      return actualizar_formulario(driver,formulario_iteracion,url)

def enviar_peticiones(driver, url, diccionario, tipo, json_fuzzing, cookie=[], iframe_posicion = -1, iframe_profundidad = 0):
   if iframe_posicion == -1:
      try:
         driver.get(url)   
      except TimeoutException:
         enviar_peticiones(driver, url, diccionario, tipo, json_fuzzing, cookie, iframe_posicion, iframe_profundidad)
      if len(cookie) > 0:
         for cookie_individual in cookie:
            driver.add_cookie(cookie_individual)
   try:
      actualizar_profundidad_iframes(driver, iframe_profundidad, iframe_posicion)
         
      iframes = len(driver.find_elements_by_tag_name("iframe"))
      if iframes != 0:
         for iframe in range(iframes):
            iframe_profundidad += 1

            enviar_peticiones(driver, url, diccionario, tipo, json_fuzzing, cookie, iframe, iframe_profundidad)
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
         for input_individual in range(len(inputs)):
            formulario.set_input(input_individual,valor)
         form_nombre = formulario.get_nombre()
         form_id = formulario.get_id()
         form_utilizar = ""
         vulnerabilidad_tiempo = formulario.enviar_peticion()
         if form_id == "":
            if form_nombre == "":
               form_utilizar = "form {0}-{1}".format(iframe_profundidad,iframe_posicion)
            else:
               form_utilizar = form_nombre
         else:
            form_utilizar = form_id

         if json_fuzzing["forms"].get(form_utilizar) is None:
            json_fuzzing["forms"].update({form_utilizar:[]})
         json_fuzzing["forms"][form_utilizar].append({"inputs":[],"tipo":tipo,"xss":False,"sqli":False,"lfi":False})
         json_fuzzing["forms"][form_utilizar][len(json_fuzzing["forms"][form_utilizar])-1]["inputs"] = formulario.get_peticion()
         if vulnerabilidad_tiempo:
            if tipo == "xss":
               json_fuzzing["forms"][form_utilizar][len(json_fuzzing["forms"][form_utilizar])-1]["xss"] = True
               #lista_posibles_vulnerabilidades["xss"].append("XSS DETECTADO En el form {0} -> \"{1}\"".format(form_utilizar,formulario.get_peticion()))
            elif tipo == "sqli":
               json_fuzzing["forms"][form_utilizar][len(json_fuzzing["forms"][form_utilizar])-1]["sqli"] = True
               #lista_posibles_vulnerabilidades["sqli"].append("SQLi DETECTADO En el form {0} -> \"{1}\"".format(form_utilizar,formulario.get_peticion()))
            elif tipo == "lfi":
               json_fuzzing["forms"][form_utilizar][len(json_fuzzing["forms"][form_utilizar])-1]["lfi"] = True
               #lista_posibles_vulnerabilidades["lfi"].append("LFI DETECTADO En el form {0} -> \"{1}\"".format(form_utilizar,formulario.get_peticion()))
            continue
         time.sleep(0.1)
   
         validarXSS(driver,json_fuzzing,form_utilizar)
         validarSQLi(driver,json_fuzzing,form_utilizar)
         validarLFI(driver,json_fuzzing,form_utilizar)
         del formulario
   return True

def validarXSS(driver, json_fuzzing, form_utilizar):
   try:
      alerta = driver.switch_to.alert
      if alerta.text is not None:
         alerta.accept()
         json_fuzzing["forms"][form_utilizar][len(json_fuzzing["forms"][form_utilizar])-1]["xss"] = True
   except NoAlertPresentException:
      json_fuzzing["forms"][form_utilizar][len(json_fuzzing["forms"][form_utilizar])-1]["xss"] = False

def validarSQLi(driver, json_fuzzing, form_utilizar):
   diccionario = Singleton_Diccionarios_validacion()
   for cadena in diccionario.get_validar_sqli():
      existe = re.search(re.compile(cadena), driver.page_source)
      if existe is not None:
         json_fuzzing["forms"][form_utilizar][len(json_fuzzing["forms"][form_utilizar])-1]["sqli"] = True
         return True
      json_fuzzing["forms"][form_utilizar][len(json_fuzzing["forms"][form_utilizar])-1]["sqli"] = False
   del diccionario

def validarLFI(driver, json_fuzzing, form_utilizar):
   diccionario = Singleton_Diccionarios_validacion()
   for cadena in diccionario.get_validar_lfi():
      existe = re.search(re.compile(cadena), driver.page_source)
      if existe is not None:
         json_fuzzing["forms"][form_utilizar][len(json_fuzzing["forms"][form_utilizar])-1]["lfi"] = True
         return True
      json_fuzzing["forms"][form_utilizar][len(json_fuzzing["forms"][form_utilizar])-1]["lfi"] = False
   del diccionario
   
def obtener_divisor_diccionario_dividido(diccionario, hilos):
   if hilos < len(diccionario):
      lotes_palabras = (len(diccionario) / hilos)
      lotes_palabras = math.floor(lotes_palabras)
      residuo_lotes_palabras = len(diccionario) % hilos
   else:
      lotes_palabras = (hilos / len(diccionario))
      lotes_palabras = math.floor(lotes_palabras)
      residuo_lotes_palabras = hilos % len(diccionario)
   return lotes_palabras,residuo_lotes_palabras

def crear_hijos_fuzzing(url, hilos, cookie=[]):
   diccionarios = Singleton_Diccionarios_ataque()
   json_fuzzing = {"forms": {}}
   for diccionario in diccionarios.get_diccionarios():
      lotes_palabras, residuo_lotes_palabras = obtener_divisor_diccionario_dividido(diccionarios.get_diccionario(diccionario), hilos)
      hijos = [] 
      for hilo in range(hilos):
         lotes_palabras_inicio = lotes_palabras * hilo
         lotes_palabras_fin = lotes_palabras * (hilo + 1)
         if hilo == hilos - 1:
            if residuo_lotes_palabras != 0:
               lotes_palabras_fin += residuo_lotes_palabras
         subdiccionario = diccionarios.get_diccionario(diccionario)[lotes_palabras_inicio:lotes_palabras_fin]
         hijos.append(Lanzar_fuzzing(hilo, "Thread-{0}".format(hilo), subdiccionario, url, diccionario, cookie))
      
      for hilo in range(hilos):
         hijos[hilo].start()

      for hilo in range(hilos):
         hijos[hilo].join()

      for hilo in range(hilos):
         forms = hijos[hilo].get_json_fuzzing_forms()
         for form in forms["forms"]:
            if form in json_fuzzing["forms"]:
               json_fuzzing["forms"][form].extend(forms["forms"][form])
            else:
               json_fuzzing["forms"][form] = forms["forms"][form]

   del diccionarios
   return json_fuzzing
   
def obtener_valores_iniciales(parametros):
   url = parametros["url"]
   hilos = parametros["hilos"]
   cookie = parametros["cookie"]
   diccionarios_ataque = Singleton_Diccionarios_ataque(strings.DICCIONARIO_ATAQUE_XSS,strings.DICCIONARIO_ATAQUE_SQLI,strings.DICCIONARIO_ATAQUE_LFI)
   diccionarios_validacion = Singleton_Diccionarios_validacion(strings.DICCIONARIO_VALIDACION_SQLI,strings.DICCIONARIO_VALIDACION_LFI)
   cookie = convertir_cookie(cookie)
   return url, hilos, cookie

def convertir_cookie(cookie):
   cookies_individuales = []
   if cookie.__contains__(","):
      subcookies = cookie.split(",")
      for subcookie in subcookies:
         cookie_individual_temporal = subcookie.split(":")
         cookies_individuales.append({"name":cookie_individual_temporal[0],"value":cookie_individual_temporal[1]})
   else:
      cookie_individual_temporal = cookie.split(":")
      cookies_individuales.append({"name":cookie_individual_temporal[0],"value":cookie_individual_temporal[1]})
   return cookies_individuales

def execute(parametros):
   url, hilos, cookie = obtener_valores_iniciales(parametros)
   json_fuzzing = crear_hijos_fuzzing(url,hilos,cookie)
   return json_fuzzing

'''
raise MaxRetryError(_pool, url, error or ResponseError(cause)) urllib3.exceptions.MaxRetryError: 
HTTPConnectionPool(host='127.0.0.1', port=35207):
Max retries exceeded with url: /session/bd53daf2431ca091ab4ed01837ee5d7e/execute/sync (Caused by NewConnectionError('<urllib3.connection.HTTPConnection object at 0x7fa8d9f4c670>:
Failed to establish a new connection: [Errno 111] Connection refused'))

Reiniciar Driver

selenium.common.exceptions.WebDriverException: Message: unknown error: net::ERR_CONNECTION_RESET
  (Session info: headless)
'''

'''
silencio = webdriver.ChromeOptions()
silencio.add_argument('headless')
driver = webdriver.Chrome()
for i in range(250):
         
   #driver.get("https://xss-game.appspot.com/level1")
   driver.get("http://altoromutual.com:8080/index.jsp")
   #driver.switch_to.frame(driver.find_element_by_tag_name("iframe"))
   query = driver.find_element_by_id("query")
   #query.send_keys("<script>alert(\"H\");</script>")
   query.send_keys(texto[i])
   #query.send_keys("HOLA")
   #button = driver.find_element_by_id("button")
   #button.click()
   try:
      query.submit()
      #print(driver.page_source)
      time.sleep(0.1)
      #print(driver.page_source)
      if driver.switch_to.alert.text is not None:
         print("XSS")
         break
   except NoAlertPresentException:
      print("Error con Alert", texto[i],i)
driver.quit()
'''