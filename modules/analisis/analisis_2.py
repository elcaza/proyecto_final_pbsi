import subprocess
import shlex
import requests
import json
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from urllib.robotparser import RobotFileParser
from fake_useragent import UserAgent
import pathlib
from bs4 import BeautifulSoup as bs
from urllib.request import urlopen
import re
import sys
from os import path
from jsmin import jsmin
from xml.etree.ElementTree import fromstring, ElementTree
from Wappalyzer import Wappalyzer, WebPage
import ssl
import os

class Utilerias():
	'''
	Esta clase contiene métodos basicos de uso recurrente en todas las demás clase
    Atributos:
        redireccionamiento:bool
            Desición si se sigue el redireccionamiento
        user_agent: object
            Objeto de la clase Useragent
	'''
	def __init__(self, cookies, redireccionamiento):
		'''
		Método de iniciación de atributos del objeto que se crea
		'''
		self.redireccionamiento = redireccionamiento
		self.user_agent = UserAgent()
		self.set_cookies(cookies)

	def get_fake_user_agent(self):
		'''
		Método que retorna un diccionario, con el valor de un agente de usuario aleatorio
		'''
		return {'User-Agent': self.user_agent.random}


	def get_peticion(self,sitio):
		'''
		Método que retorna el resultado de una petición, si esta genera algún error, retornará una cadena vacia
		Parametros:
			sitio: Url del sitio a consultar
		'''
		try:
			if sitio.startswith("https"):
				respuesta = requests.get(sitio,headers=self.get_fake_user_agent(),verify=False,cookies=self.cookie)
			else:
				respuesta = requests.get(sitio,headers=self.get_fake_user_agent(),cookies=self.cookie)
		except Exception as e:
			respuesta = ""
		return respuesta

	def obtener_path_file(self,relative_path,file_name,extension):
		'''
		Método retorna la ruta en donde se encuentra el programa, unida con un archivo y su extesión
		Parametro:
			relative_path: Ruta absoluta de la ubicación
			file_name: Nombre del archivo
			extension: Estension del archivo
		'''
		abs_path = pathlib.Path(__file__).parent.absolute()
		return str(abs_path)+"/"+relative_path+file_name+extension

	def directorio_existente(self,sitio,nivel_deep=0):
		'''
		Método que verifica que exista el directorio solicitado, en el sitio
		Parametros:
			sitio: Url del sitio
			nivel_deep: nivel de profundidad
		'''
		existe = False
		respuesta = self.get_peticion(sitio)
		codigo_estado = -1
		if respuesta != "":
			if len(respuesta.history) > 0:
				codigo_estado = respuesta.history[-1].status_code
			if respuesta.status_code == 200 and not (codigo_estado > 301 and codigo_estado <= 310):
				existe = True

		return  existe

	def obtener_contenido_html(self,sitio):
		'''
		Método que obtiene el contenido de la página
		Parametros:
			sitio: URL del sitio
		'''
		try:
			respuesta = self.get_peticion(sitio)
			if respuesta != "":
				return BeautifulSoup(respuesta.content, "html.parser")
		except:
			return ""

	def buscar_archivo_comun(self,lista_urls):
		'''
		Método que revisa la existencia de un archivo en el sitio 
		Parametros:
			lista_urls: listado de archivos comunes
		Retorna:
			files_comunes: URL's con los archivos que generan una respuesta con código 200
		'''
		files_comunes = []
		i = 0
		for url in lista_urls:
			respuesta = self.get_peticion(url)
			if respuesta != "":
				if (respuesta.status_code == 200) and self.directorio_existente(url):
					files_comunes.append(url)
			i += 1
		return files_comunes

	def generar_urls(self,sitio,lista_urls):
		'''
		Método que busca la exitencia de archivos omunes para el cms
		Parametros:
			sitio: string
				URL del sitio
			lista_urls: string
				lista de archivos comunes
		Retorna:
			urls: list
				URL del sitio, y de los archivos concatenados.
		'''
		urls = []
		for url in lista_urls:
			if sitio[-1] == "/":
				urls.append(sitio + url)
			else:
				urls.append(sitio + "/" + url)
		return urls

	def escaner_cms_vulnes(self,cms,version):
		'''
		Método que escanea las vulnerabiliades
		Parametros:
		cms: string
			nombre del cms identificado
		version: string
			versión correspondiente al cms
		'''
		db = True
		if (db):
			vulnes = self.carga_vulnerabilidades(cms)
			if not(vulnes):
				vulnes = self.buscar_vulnerabilidades(cms)
				self.actualizar_vulnerabilidades(cms,vulnes)
		else:
			vulnes = self.buscar_vulnerabilidades(cms)
			self.actualizar_vulnerabilidades(cms,vulnes)
		regex_vulnes = re.compile("("+version+")")
		return self.identificar_vulnerabilidades(vulnes,regex_vulnes)

	def carga_vulnerabilidades(self,nombre_db):
		'''
		Método que carga la lista de vulnerabilidades en el archivo correspondiente a la versión del cms
		Parametros:
			nombre_db: string
				Nombre del cms, el cual se consultara su archivo de vulnerabilidades
			Retorna:
				datos: dic
					Diccionario de las vulnerabilidades con su descripción
		
		'''
		abs_path = pathlib.Path(__file__).parent.absolute()
		abs_path = str(abs_path) + "/vulnes_db/" + nombre_db + ".json"
		try:
			with open(abs_path) as db:
				datos = json.load(db)
			return datos
		except:
			print("Error al abrir archivos de base de datos")
			return False

	def buscar_vulnerabilidades(self,cms):
		'''
		Método que busca vulnerabilidades deacuerdo a la versión del CMS, en la pagina del mitre

		Parametros:
			cms: string
				nombre del cms
		Retorna: 
			vulnes: array
			Un arreglo con vulnerabilidades asociadas a la version del cms
		'''
		url_cve_mitre = "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=" + cms
		soup = self.obtener_contenido_html(url_cve_mitre)
		table = soup.find('div', id="TableWithRules")
		rows = table.findAll('tr')
		rows.pop(0)
		vulnes = []
		for row in rows:
			cve = row.find(nowrap = "nowrap").text
			description = row.findChildren(valign = "top")[1].text
			vulnes.append({"cve":cve,"description":description})
		return vulnes

	def actualizar_vulnerabilidades(self, nombre_db, vulnes):
		'''
		Método que actualiza las vulnerabilidades en el archivo correspondiente al cms
		Parametros:
			nombre_db: string
				Nombre del cms
			vulnes: dic
				Diccionario, que ontiene el identificador de la vulnerabilidad, con su descripción
		'''
		abs_path = pathlib.Path(__file__).parent.absolute()
		abs_path = str(abs_path) + "/vulnes_db/" + nombre_db + ".json"
		try:
			with open(abs_path, "w") as db:
				json.dump(vulnes,db)
		except:
			print("Error no se puede abrir el archivo de vulnerabilidades")

	def identificar_vulnerabilidades(self, vulnes_db, regex):
		'''
		Método que la filtración de vulnerabilidades, por medio de la version
		Parametros:
			vulnes_db: dic
				Lista que contiene la vulnerabilidades con su descripción
			regex: string
				Expresión regular, que contiene la versión de busuqeda
		Retorna:
			vulnes_cms: list
				Lista de vulnerabilidades con su descripción
		'''
		vulnes_cms = []
		for vulnerabilidad in vulnes_db:
			cve = vulnerabilidad['cve']
			description = vulnerabilidad['description']
			if regex.search(description):
				vulnes_cms.append({"cve":cve,"description":description})
		return vulnes_cms

	def get_cookies(self):
		return self.cookie

	def set_cookies(self, cookie):
		'''
		Método que obtiene la cookie ingresada por el usuario
		Parametro: 
			cookie: string
				cookie de sesión
		'''
		cookies = {}
		if len(cookie) != 0:
			cookies_tmp = []
			c_tmp = []
			cookies_data = cookie
			if "," in cookies_data:
				cookies_tmp = cookies_data.split(",")
				for cookie in cookies_tmp:
					c_tmp = cookie.split(":")
					cookies[c_tmp[0]] = c_tmp[-1]
			else:
				cookies_tmp = cookies_data.split(":")
				cookies[cookies_tmp[0]] = cookies_tmp[1]
		self.cookie = cookies

class Wordpress():
	'''
	Clase que ontiene información de y la realiza al comprobación con respecto al sitio
	si este se trata de un cms wordpress

	Atributos:
		redireccionamiento: bool
			Booleano que contiene, la desición si se seguira o no la redirección 
		util: object
			Objeto de la clase Utilerias
		cookie: string
			Cookie de sesion
	'''
	def __init__(self,sitio, cookie, redireccionamiento):
		'''
		Método de inicialización de atributos
		'''
		print("Woordpress")
		self.redireccionamiento = redireccionamiento
		self.util = Utilerias(cookie, self.redireccionamiento)
		self.sitio = sitio
		self.cookie = cookie

	def inicio_wordpress(self,deteccion_cms,tmp_diccionario):
		'''
		Método de llamada a alas funciones de obtención de información
		Parametros: 
			deteccion_cms: bool
				Contiene el resultado de la detección del cms
			tmp_diccionario: dic
				Diccionario que contendrá la información del cms
		'''
		info = self.carga_configuracion()
		tmp_cms = {}
		tmp_cms["nombre"] = "wordpress"
		tmp_cms["version"] = self.obtener_version_wordpress()
		tmp_diccionario["cms"] = tmp_cms
		informacion_expuesta = self.obtener_informacion_sensible(info)
		tmp_diccionario["plugins"] = informacion_expuesta.pop("plugins")
		tmp_diccionario["librerias"] = []
		tmp_diccionario["archivos"] = informacion_expuesta.pop("exposed_files")
		if(tmp_cms["version"] != ""):
			tmp_diccionario["vulnerabilidades"] = self.obtener_vulnerabilidades(tmp_cms["version"])
		else:
			tmp_diccionario["vulnerabilidades"] = []


	def obtener_informacion_sensible(self,wordpress_info):
		'''
		Método que recoíla la información sensible, es decir archivos comunes
		Parametros:
			wordpress_info: dict
				Información recuperada de los archivos

		'''
		informacion_recopilada = {}
		for info in wordpress_info:
			if info["type"] == "json":
				respuesta = self.util.get_peticion(path.join(self.sitio,info["resource"]))
				if respuesta != "":
					try:
						datos = json.loads(respuesta.text)
						n = []
						for d in datos:
							n.append(d[info["key"]])
						informacion_recopilada[info["info"]] = n
					except json.decoder.JSONDecodeError:
						informacion_recopilada[info["info"]] = []
			if info["type"] == "file":
				archivos_expuestos = []
				for archivo in info["dir_files"]:
					respuesta = self.util.get_peticion(path.join(self.sitio,archivo))
					if respuesta != "":
						status_code_redirect = -1
						#if len(respuesta.history) > 0:
							#status_code_redirect = respuesta.history[0].status_code
						if respuesta.status_code == 200:
							archivos_expuestos.append(archivo)
						else:
							respuesta = requests.post(path.join(self.sitio,archivo),headers=self.util.get_fake_user_agent(),verify=False,cookies=self.util.get_cookies(),allow_redirects=self.redireccionamiento)
							if len(respuesta.history) > 0:
								status_code_redirect = respuesta.history[0].status_code
							if respuesta.status_code == 200 and not (status_code_redirect > 301 and status_code_redirect <= 310):
								archivos_expuestos.append(archivo)
				informacion_recopilada[info["info"]] = archivos_expuestos
		return informacion_recopilada



	def obtener_version_wordpress(self):
		'''
		Método que obtiene la versión de wordpress
		Retorna:
			version: string
				La versión o si no se detecto, contiene la palabra "Desconocida"
		'''
		version = self.busqueda_tag_meta()
		if(version=="Desconocida"):
			respuesta = self.util.get_peticion(path.join(self.sitio,"feed"))
			if respuesta != "":
				match = self.expresion_regular("[0-9].*</generator",respuesta.text)
				if match != None:
					match = self.expresion_regular("[0-9].*<",match)
					version = match[:-1]
				else:
					respuesta = self.util.get_peticion(path.join(self.sitio,"readme.html"))
					if respuesta != "":
						if(match != None):
							version = self.expresion_regular("[0-9][0-9|.]*",match)
						else:
							dominio = self.obtener_dominio()
							for enlace in self.obtener_enlaces(self.sitio,dominio):
								if self.expresion_regular("\.[png|jpg].*",enlace) == None:
									version = self.busqueda_tag_meta(enlace)
									if (version != "Desconocida"):
										break
		return version

	def obtener_enlaces(self,url_sitio,filter=""):
		'''
		Método que obtiene los enlaces que se encuentran en el código de la pagina
		Parametros:
			url_sitio: string
				Contiene la url del sitio
			filter:string
				Contiene el dominio del sitio que se va a concatenar con la expresión regular
		Retorna:
			enlaces: list
				Lista de enlaces
		'''
		enlaces = None
		try:
			r = requests.get(url_sitio,headers=self.util.get_fake_user_agent(),allow_redirects=self.redireccionamiento)
			enlaces = re.findall("https?://"+filter+"[\w|/|\.|\?|=|-]*",r.text)
			return enlaces
		except requests.exceptions.ConnectionError:
			return enlaces

	def expresion_regular(self,expresion,contenido):
		'''
		Método que valida una expresión regular en el contenido proporcionado
		Parametros:
			expresion: string
				Espresión a validar
			contenido:string
				Contenido o texto a en el que se va a validar
		Retorna:
			El contenido o en su defecto None
		'''
		match = re.search(expresion,contenido)
		if(match != None):
			return contenido[match.span()[0]:match.span()[1]]
		return None

	def busqueda_tag_meta(self):
		'''
		Método que busca el nombre del cms en el código de la pagina
		Retorna:
			La versión del cms o en su defecto la palabra "Desconocida"
		'''
		respuesta = self.util.get_peticion(self.sitio)
		if respuesta != "":
			match = self.expresion_regular("content=\"[w|W]ord[p|P]ress.*>",respuesta.text)
			if(match != None):
				match = self.expresion_regular("[0-9].*\"",match)
				return match[:-1]
		return "Desconocida"

	def obtener_dominio(self):
		'''
		Método que obtiene el dominio del sitio
		Retorna:
			La url del sitio
		'''
		indices = []
		for match in re.finditer("/",self.sitio + "/"):
			indices.append(match.start())
		return self.sitio[indices[1]+1:indices[2]]


	def detect_cms(self):
		'''
		Método que realiza la detección del para el cms wordpress
		Retorna:
			El nombre del cms si este se detecto, si no es asi comienza retorna None
		'''
		resultado = False
		respuesta = self.util.get_peticion(self.sitio)
		if respuesta != "":
			if respuesta.headers.get("Link") != None and "wp-json" in respuesta.headers["Link"]:
				resultado = True
			elif respuesta.headers.get("Set-Cookie") != None and re.search(".*[w|W]ord[p|P]ress.*",respuesta.headers["Set-Cookie"]):
				resultado = True
			else:
				respuesta = self.util.get_peticion(path.join(self.sitio,"readme.html"))
				if respuesta != "":
					if(respuesta.ok and re.search("[w|W]ord[p|P]ress",respuesta.text) != None):
						resultado = True
					elif self.util.directorio_existente(path.join(self.sitio,"wp-includes")):
						resultado = True
					elif self.util.directorio_existente(path.join(self.sitio, "wp-content")):
						resultado = True

		if resultado:
			return "wordpress"

		return None

	def carga_configuracion(self):
		'''
		Método que carga la información del diccionario, contenido en un archivo
		Retorna:
			informacion: dic
				Diccionario con toda la información que se tiene del cms wordpress
		'''
		config_file = self.util.obtener_path_file("config/","config_wordpress",".json")
		#print(config_file)
		with open(config_file) as configuracion:
			datos = jsmin(configuracion.read())
			config = json.loads(datos)
			informacion = config["wordpress"]
			return informacion

	def obtener_vulnerabilidades(self,version):
		'''
		Método que obtiene las vuñnerabilidades relacionadas con el cms y la versión
		Parametros:
			version: string
				Versión del cms
		Retorna:
			lista_vulnerabilidades: list
				Lista de identifiadores de vulnerabilidades, asociadas al cms y a la versión
		'''
		tmp = []
		tmp = version.split('.')
		if len(tmp) < 2:
			return []
		vulnerabilidades = self.util.escaner_cms_vulnes("wordpress",version)
		lista_vulnerabilidades = []
		if (len(vulnerabilidades) != 0):
			for element in vulnerabilidades:
				lista_vulnerabilidades.append(element.get("cve"))
				#lista_vulnerabilidades.append(element.get("description"))
		return lista_vulnerabilidades

class Moodle():
	'''
	Clase que ontiene información de y la realiza al comprobación con respecto al sitio
	si este se trata de un cms wordpress

	Atributos:
		redireccionamiento: bool
			Booleano que contiene, la desición si se seguira o no la redirección 
		util: object
			Objeto de la clase Utilerias
		cookie: string
			Cookie de sesion
	'''
	def __init__(self,sitio, cookie, redireccionamiento):
		'''
		Método de inicialización de atributos de la clase 
		'''
		print("Moodle")
		self.url = sitio
		self.redireccionamiento = redireccionamiento
		self.util = Utilerias(cookie, self.redireccionamiento)


	def inicio_moodle(self,deteccion_cms,tmp_diccionario):
		'''
		Método de llamada a alas funciones de obtención de información
		Parametros: 
			deteccion_cms: bool
				Contiene el resultado de la detección del cms
			tmp_diccionario: dic
				Diccionario que contendrá la información del cms
		'''
		info = self.carga_configuracion()
		tmp_cms = {}
		tmp_cms["nombre"] = "moodle"
		tmp_cms["version"] = self.detect_version(info["version_file"])
		tmp_diccionario["cms"] = tmp_cms
		tmp_diccionario["plugins"] = self.get_plugins_moodle(info["plugs"])
		tmp_diccionario["librerias"] = self.get_librerias_moodle(info["libs"])
		tmp_diccionario["archivos"] = self.get_archivos_moodle(info["dir_files"])
		tmp_diccionario["vulnerabilidades"] = self.detect_vulnerabilidades(tmp_cms["version"])

	def get_plugins_moodle(self,location_of_plugins):
		'''
		Método de busqueda de plugins del cms
		Parametros:
			location_of_plugins: list
				Lista de los plugins de comprobación
		Retorna:
			list_plugins: list
				Lista de plugins verificados 
		'''
		plugins_for_verify = []
		for location_plugin in location_of_plugins:
			if self.url[-1] =="/":
				plugins_for_verify.append(self.url + location_plugin.strip())
			else:
				plugins_for_verify.append(self.url + "/" + location_plugin.strip())
		plugins_raw = self.util.buscar_archivo_comun(plugins_for_verify)
		if len(plugins_raw) == 0:
			return ["No se encontraron plugins."]
		else:
			plugins = []
			for plugin_raw in plugins_raw:
				plugins.append(plugin_raw[len(self.url):plugin_raw.rfind("/")])
			list_plugins=[]
			for plugin in plugins:
				list_plugins.append(plugin)
			return list_plugins

	def get_librerias_moodle(self,librerias):
		'''
		Método de obtención de libreiras utilizadas en el cms moodle
		Parametros:
			librerias: string
				Ruta del archivo que contiene el listado de librerias
		Retorna:
			lista_libreria: list
				Lista de las librerias que se han comprobado que contiene el cms
			Lista vacia si no se encontro ninguna libreria
		'''
		tmp_libreria = {}
		tmp_version = []
		if self.url[-1] == "/":
			tmp_url = self.url + librerias
		else:
			tmp_url = self.url + "/" + librerias

		respuesta = self.util.get_peticion(tmp_url)
		if respuesta != "":
			if respuesta.status_code == 200 and self.util.directorio_existente(tmp_url):
				lib_ver = {}
				tree = ElementTree(fromstring(respuesta.content))
				root = tree.getroot()
				lista_librerias = []
				for directorio in root:
					libreria = directorio[1].text
					version_libreria = directorio[3].text
					if type(version_libreria) == type(None):
						version_libreria = ""
					lib_ver[libreria] = version_libreria
					tmp_libreria = {}
					tmp_version = []
					tmp_version.append(version_libreria)
					tmp_libreria["nombre"] = libreria
					tmp_libreria["version"] = tmp_version
					lista_librerias.append(tmp_libreria)
				return lista_librerias
		else:
			return []

	def get_archivos_moodle(self,dir_archivos):
		'''
		Método que obtienen los archivos expuestos en el cms
		Parametros: 
			dir_archivos: list
				Listado de archivos contenidos en el diccionario del cms
		Retorna:
			lista_archivos: list
				Lista de archivos, que se comprobaron que se encuentran expuestos
			En su defecto una lista vacia
		'''
		verificar_archivos = []
		for localizar_archivo in dir_archivos:
			if self.url[-1] == "/":
				verificar_archivos.append(self.url + localizar_archivo.strip())
			else:
				verificar_archivos.append(self.url + "/" + localizar_archivo.strip())
		archivos = self.util.buscar_archivo_comun(verificar_archivos)
		if len(archivos) == 0:
			return []
		else:
			lista_archivos = []
			for archivo in archivos:
				lista_archivos.append(archivo)
			return lista_archivos


	def detect_version(self,version_file):
		'''
		Método que obtiene la versión del cms
		Parametros:
			version_file: string
				Ruta del archivo que contiene la informacióon de la versión
		Retorna:
			version: string
				Versión del cms
			Si no lo detecta regresa una cadena vacia
		'''
		if self.url[-1] == "/":
			temp_url = self.url + version_file
		else:
			temp_url = self.url + "/" + version_file

		respuesta = self.util.get_peticion(temp_url)
		if respuesta != "":
			if respuesta.status_code == 200 and self.util.directorio_existente(temp_url):
				tmp_1 = respuesta.text.find("===")
				tmp_1 += 3
				tmp_2 = respuesta.text[tmp_1:].find("===")
				tmp_2 += tmp_1
				version = respuesta.text[tmp_1:tmp_2].strip()
				version = version[:3]
			else:
				version = ""
		return version

	def detect_cms(self):
		'''
		Método que detecta si se trata del cms
		Retorna:
		El nombre del cms (moodle) o en su defecto None
		'''
		cont = 0
		config_moodle = self.carga_configuracion()
		if len(config_moodle["directorios"]) > 10:
			for directorio_root in config_moodle["directorios"]:
				if self.url[-1] =="/":
					temp_url = self.url + directorio_root
				else:
					temp_url = self.url + "/" + directorio_root
				respuesta = self.util.get_peticion(self.url)
				if respuesta != "":
					if respuesta.status_code == 200 and self.util.directorio_existente(self.url):
						cont += 1
			if cont > 5:
				respuesta = self.util.get_peticion(self.url)
				if respuesta == "":
					return None
				if config_moodle["identifier"] in respuesta.text:
					return "moodle"
		return None

	def carga_configuracion(self):
		'''
		Método que carga la configuración del cms (moodle)
		Retorna:
			informacion: dict
				Informacón relacionada con el cms
		'''
		config_file = self.util.obtener_path_file("config/","config_moodle",".json")
		with open(config_file) as configuracion:
			datos = json.load(configuracion)
			informacion = datos["moodle"]
			return informacion

	def detect_vulnerabilidades(self,version):
		'''
		Método que detecta las vulnerabilidades con respecto al cms y su versión
		Parametros:
			version: string
				Versión del cms
		Retorna
			lista_vulnerabilidades: list
				Lista de vulnerabilidades encontradas
		'''
		tmp = []
		tmp = version.split('.')
		if len(tmp) < 2:
			return []
		vulnerabilidades = self.util.escaner_cms_vulnes("moodle",version)
		lista_vulnerabilidades = []
		if (len(vulnerabilidades) == 0):
			if version == "":
				return []
		else:
			for element in vulnerabilidades:
				lista_vulnerabilidades.append(element.get("cve"))
				lista_vulnerabilidades.append(element.get("cve"))
				#lista_vulnerabilidades.append(element.get("description"))
		return lista_vulnerabilidades

class Drupal():
	'''
	Clase que ontiene información de y la realiza al comprobación con respecto al sitio
	si este se trata de un cms wordpress

	Atributos:
		redireccionamiento: bool
			Booleano que contiene, la desición si se seguira o no la redirección 
		util: object
			Objeto de la clase Utilerias
		cookie: string
			Cookie de sesion
	'''
	def __init__(self,sitio, cookie, redireccionamiento):
		print("Drupal")
		self.url = sitio
		self.redireccionamiento = redireccionamiento
		self.util = Utilerias(cookie, self.redireccionamiento)

	def inicio_drupal(self,deteccion_cms,tmp_diccionario):
		'''
		Método de llamada a alas funciones de obtención de información
		Parametros: 
			deteccion_cms: bool
				Contiene el resultado de la detección del cms
			tmp_diccionario: dic
				Diccionario que contendrá la información del cms
		'''
		tmp_cms = {}
		config = self.carga_configuracion()
		version = self.get_version_wappalyzer()
		if version == None:
			version = self.detect_version(config)
		try:
			ver = version.strip().split('.')[0]
		except:
			ver = version
		modulos = config['directorios'][0][ver][0]['modules']
		#print(modulos)
		archivos = config['directorios'][0]['expuestos']
		tmp_cms["nombre"] = "drupal"
		tmp_cms["version"] = version
		tmp_diccionario["cms"] = tmp_cms
		tmp_diccionario["plugins"] = self.realiza_peticiones(modulos,"modulos",300)
		tmp_diccionario["librerias"] = []
		tmp_diccionario["archivos"] = self.realiza_peticiones(archivos,"archivos visibles")
		tmp_diccionario["vulnerabilidades"] = self.detect_vulnerabilidades(version)

	def detect_version(self,config):
		'''
		Método de detección del cms
		Parametros:
			config: dict
				Diccionario que contiene la información recaba de los archivos de configuración
		Retorna:
			version: string
				La versión del cms detectado
			Si no se encuentra una versión, regrea una cadena vacia
		'''
		version = None
		drupal_7 = config['directorios'][0]['drupal_7'][0]['files']
		drupal_8 = config['directorios'][0]['drupal_8'][0]['files']
		version_7 = self.calcula_codigos(self.url, drupal_7)
		version_8 = self.calcula_codigos(self.url, drupal_8)
		version = "8.x" if version_8 > version_7 else "7.x"
		if version == "7.x":
			archivos = config['directorios'][0]["7"][0]['files']
			for archivo in archivos:
				#print(self.url + archivo)
				respuesta = self.util.get_peticion(self.url + archivo)
				if respuesta != "":
					code = str(respuesta.status_code)[0]
					if code != '4' and code != '3':
						if archivo == "CHANGELOG.txt":
							version = " " + respuesta.text.split(',')[0].split(' ')[1]
		if version:
			return version
		return ""

	def get_version_wappalyzer(self):
		'''
		Método que obtiene la versión por medio del modulo de Wappalyzer
		Retorna:
			version:
				Valor de la versión del cms
		'''
		version = None
		wappalyzer = Wappalyzer.latest()
		webpage = WebPage.new_from_url(self.url,verify=False)
		tmp = wappalyzer.analyze_with_versions_and_categories(webpage)
		for llave,valor in tmp.items():
			if "drupal" in  llave.lower():
				for llave2,valor2 in valor.items():
					if llave2 == "versions":
						if len(valor2):
							version = valor2[0]
		return version


	def calcula_codigos(self,url,archivos):
		'''
		Método que comprueba si alguno de los archivo se puede consultar mediante la url
		Parametros:
			url : string
				URL o enlace del sitio
			archivos: list
				Lista de archivos obtenida del archivo de información
		Retorna:
			peticion:int
				Número de peticiones exitosas
		'''
		peticiones = 0
		for archivo in archivos:
			respuesta = self.util.get_peticion(self.url + archivo)
			if respuesta != "":
				if respuesta.status_code != 404:
					peticiones += 1
		return peticiones if peticiones > 0 else 0


	def detect_cms(self):
		'''
		Detecta si el sitio, probado es un cms (drupal)
		Retorna:
			Nombre del cms o si no se detecto ue se trate de drupal regresa None
		'''
		try:
			config_drupal = self.carga_configuracion()
		except:
			config_drupal = None
		respuesta = self.util.get_peticion(self.url)
		if respuesta != "" and config_drupal != None:
			respuesta_head = str(respuesta.headers)
			respuesta_get = str(respuesta.text)
			root = self.url
			if config_drupal:
				cabeceras = config_drupal['cabeceras']
				cuerpo = config_drupal['cuerpo']
				busca = config_drupal['directorios'][0]['root']
				if self.busca_respuesta(cabeceras,respuesta_head) or self.busca_respuesta(cuerpo, respuesta_get) or self.detectar_meta():
					return "drupal"
		return None

	def carga_configuracion(self):
		'''
		Método que carga la informacióna una variable para el manejo de esta
		Retorna:
			datos: dict
				Diccionario de datos, del cms drupal
		'''
		config_file = self.util.obtener_path_file("config/","config_drupal",".json")
		with open(config_file) as configuracion:
			datos = json.load(configuracion)
			return datos["drupal"][0]
		print("No se pudo abrir archivo de configuracion")
		return None

	def busca_respuesta(self, elementos, respuesta):
		cont = 0
		for elemento in elementos:
			if elemento in respuesta:
				cont += 1
		return True if cont > 0 else False

	def detectar_meta(self):
		'''
		Método que detecta la version del cms por medio del código de pagina
		Retorna:
			True: Si se detecta el cms y la version
			False: Si no se detecta la etiqueta
		'''
		gcontext = ssl.SSLContext()
		try:
			html = urlopen(self.url,context=gcontext)
			bs_object = bs(html,features="html.parser")
			exp_regular = r'Drupal [7-9].*'
			for tag in bs_object.findAll("meta",{"content":re.compile(exp_regular)}):
				if re.search(exp_regular, str(tag)):
					return True
			return False
		except:
			return False

	def realiza_peticiones(self,recursos,busqueda,codigo=0):
		'''
		Método que realiza las peticiones, que comprueban la exitencia de algún recurso
		Parametros:
			rescursos: list
				Lista de recuros a comprobar
			busqueda: string
				Recurso que se quiere buscar
		Retorna:
			result_list: list
				Lista de recursos encontrados
		'''
		result_list = list()
		for recurso in recursos:
			req = self.util.get_peticion(self.url + recurso)
			if req != "":
				if busqueda == "modulos":
					if req.status_code not in range(codigo, codigo + 99) and req.status_code != 404:
						result_list.append(recurso)
				elif busqueda == "archivos visibles":
					if req.status_code == 200:
						result_list.append(recurso)
		return result_list

	def detect_vulnerabilidades(self,version):
		'''
		Método que detecta las vulnerabilidades correspondientes al cms y a la versión
		Parametros:
			version: string
				contiene la versión de rupal detectada
		Retorna:
			lista_vulnes: list
				Lista de vulnerabilidades detectadas.
		'''
		tmp = []
		tmp = version.split('.')
		if len(tmp) < 2:
			return []
		if version != "":
			vulnerabilidades  = self.util.escaner_cms_vulnes("drupal",version)
			if len(vulnerabilidades) > 0:
				lista_vulnes = list()
				for vul in vulnerabilidades:
					lista_vulnes.append(vul.get("cve"))
				return lista_vulnes
			return []
		else:
			return []

class Joomla():
	'''
	Método de detección del cms
	Parametros:
		config: dict
			Diccionario que contiene la información recaba de los archivos de configuración
	Retorna:
		version: string
			La versión del cms detectado
		Si no se encuentra una versión, regrea una cadena vacia
	'''
	def __init__(self,sitio, cookie, redireccionamiento):
		print("Joomla")
		self.url = sitio
		self.redireccionamiento = redireccionamiento
		self.util = Utilerias(cookie, self.redireccionamiento)

	def inicio_joomla(self,deteccion_cms,tmp_diccionario):
		'''
		Método de llamada a alas funciones de obtención de información
		Parametros: 
			deteccion_cms: bool
				Contiene el resultado de la detección del cms
			tmp_diccionario: dic
				Diccionario que contendrá la información del cms
		'''
		tmp_cms = {}
		tmp_cms["nombre"] = "joomla"
		tmp_cms["version"] = self.obtener_version_joomla()
		tmp_diccionario["cms"] = tmp_cms
		tmp_diccionario["plugins"] = []
		tmp_diccionario["librerias"] = []
		tmp_diccionario["archivos"] = self.obtener_archivos_joomla(self.util.generar_urls(self.url,self.cargar_configuracion()))
		tmp_diccionario["vulnerabilidades"] = self.obtener_vulnerabilidades(tmp_cms["version"])

	def obtener_version_joomla(self):
		'''
		Método que obtiene la versión del cms, mediante el código fuente
		Retorna:
			La versión del cms
		'''
		soup = self.util.obtener_contenido_html(self.url+"README.txt")
		for linea in (soup.text).splitlines():
			regex = re.compile("([Jj]oomla!)*\d*\.\d\s([Vv]ersion)")
			if regex.search(linea):
				break
		version = re.findall("\d+\.\d+",linea)
		return version[0]

	def obtener_archivos_joomla(self,urls):
		'''
		Método que obtiene los archivos expuestos
		Parametros:
			urls: list
				Lista de archivos, que se obtiene de la información recabada
		Retorna:
			archivos_detectados: list
				Lista de archivos detectados
		'''
		archivos_detectados = []
		for archivo in urls:
			respuesta = self.util.get_peticion(archivo)
			if respuesta != "":
				if respuesta.status_code == 200:
					archivos_detectados.append(archivo)
		return archivos_detectados

	def detect_cms(self):
		'''
		Método que detecta si se trata del cms (joomla)
		Retorna:
			Retorna joomla, si se detecta, si no se detecta regresa None
		'''
		joomla_encontrado = False
		if not joomla_encontrado:
			joomla_encontrado = self.checar_meta_joomla()
		if not joomla_encontrado:
			joomla_encontrado = self.checar_dom_elements()
		if not joomla_encontrado:
			joomla_encontrado = self.checar_administrador_pagina()
		return ("joomla") if joomla_encontrado else (None)

	def checar_meta_joomla(self):
		'''
		Método que checa a la eqtiqueta meta, del código para detectar el cms
		'''
		soup = self.util.obtener_contenido_html(self.url)
		if soup != "":
			return self.buscar_joomla(soup, "meta",{'name':'generator'},"joomla")

	def checar_dom_elements(self):
		'''
		Método que checa en el dom si se encuentra el cms
		'''
		soup = self.util.obtener_contenido_html(self.url)
		if soup != "":
			return self.buscar_joomla(soup, "script", {'class':re.compile('(joomla*)')},"joomla")

	def checar_administrador_pagina(self):
		'''
		Método que busca en la página de administración el cms qu se esta ocupando
		Retorna:
			True: si se encuentra el cms joomla
			False: si no s encuentra que se trata del cms joomla
		'''
		soup = self.util.obtener_contenido_html(self.url+"/administrator")
		if soup != "":
			if (self.buscar_joomla(soup, "img", {'src':re.compile('(joomla*)')}, "joomla") | self.buscar_joomla(soup, "a", {'class':re.compile('(joomla*)')}, "joomla")):
				return True
			else:
				return False

	def buscar_joomla(self,soup,tag,attrs_objeto,if_containts):
		'''
		Método que que busca el contenido y la expresión regular a buscar
		Parametros:
			soup: object
				Contenido de la página que se solicito
			tag: string
				Eqtiqueta de código las cuales se vana analizar su contenido
			attrs_objeto: dic
				Diccionario con la expresión a buscar
			if_containts: string
				Cadena que se va a buscar en el contenido
		Retorna:
			True: Si se comprueba que en el contenido se encuentra la cadena
			False: Si no se comprueba que en el contenido exista la cadena
		'''
		if attrs_objeto is not None:
			metatags = soup.find_all(tag,attrs=attrs_objeto)
			for tag in metatags:
				if (if_containts in str(tag).lower()):
					return True
		
		return False

	def cargar_configuracion(self):
		'''
		Método que carga la configuración del archivo de joomla
		Retorna:
			routes: list
				Listado de archivos
		'''
		try:
			configuracion = self.util.obtener_path_file("config/","config_joomla",".json")
			with open(configuracion) as json_archivo:
				datos = json.load(json_archivo)
				routes = datos["routes"]
				return routes
		except IOError:
			print("Entra aqui")
			exit()

	def obtener_vulnerabilidades(self,version):
		'''
		Método que obtiene las vulnerabilidades del cms con la versión
		Parametros:
			version: string
				Versión detectada del cms
		Retorna:
			lista_vulnerabilidades:list
				Lista de vulnerabilidades encontradas
		'''
		tmp = []
		tmp = version.split('.')
		if len(tmp) < 2:
			return []
		vulnerabilidades = self.util.escaner_cms_vulnes("joomla",version)
		lista_vulnerabilidades = []
		if (len(vulnerabilidades) == 0):
			if version == "":
				return []
		else:
			for element in vulnerabilidades:
				lista_vulnerabilidades.append(element.get("cve"))
				#lista_vulnerabilidades.append(element.get("description"))
			return lista_vulnerabilidades

class Obtener_IOC():

	'''
	Clase que contiene metodos los para comprobar que los indicadores de compromisos se activan
	Atributos:
		redireccionamiento: bool
			Variable que contiene la desición de seguir con la redirección
		cookie:string
			Variable que contiene la o las cookies de sesión
		sitio:string
			Contiene la url del sitio
		tmp_diccionario:dic
			Diccionario de información que se recolectará en la clase
		ioc_anomalo:bool
			Indicador de existencia de contenido anomalo
		ioc_miner:bool
			Indicador de existencia de contenido de minador
		webshell_ioc:bool
			Indicador de existencia de contenido de webshell
		ejecutable_ioc:bool
			Indicador de existencia del ejecutable
	'''
	def __init__(self,sitio, cookie, tmp_diccionario,redireccionamiento):
		print("IOC")
		self.redireccionamiento = redireccionamiento
		self.cookie = cookie
		self.tmp_diccionario = tmp_diccionario
		self.sitio = sitio
		self.ioc_anomalo = False
		self.ioc_miner = False
		self.webshell_ioc = False
		self.ejecutable_ioc = False
		self.tmp_diccionario["ioc_anomalo"] = {"existe":self.ioc_anomalo,"valores":[]}
		self.tmp_diccionario["ioc_webshell"] = {"existe":self.webshell_ioc,"valores":[]}
		self.tmp_diccionario["ioc_cryptominer"] = {"existe":self.ioc_miner,"valores":[]}
		self.tmp_diccionario["ioc_ejecutables"] = {"existe":self.ejecutable_ioc,"valores":[]}
		self.util = Utilerias(self.cookie, self.redireccionamiento)
		self.ejecutar_ioc()

	def ejecutar_ioc(self):
		'''
		Método que controla la ejecución de los métodos para la desición del indicador de compromiso
		'''
		self.ioc_contenido_anomalo()
		self.ioc_cryptominer()
		self.ioc_webshell()
		self.ioc_ejecutables()

	def ioc_contenido_anomalo(self):
		'''
		Método que realiza la comprobación de contenido anomalo en el sitio
		'''
		print("IOC Anomalo")
		contenido_a = self.util.obtener_contenido_html(self.sitio)
		ruta = path.abspath(path.dirname(__file__)) + "/config/config_ioc.json"
		with open(ruta,"r") as ci:
			diccionarios = json.load(ci)
		ci.close()
		venta = diccionarios["contenido_anomalo"]["diccionario_ventas"]
		anomalo = diccionarios["contenido_anomalo"]["diccionario_anomalo"]
		contador_venta = 0
		contador_anomalo = 0
		for palabra_v in venta:
			palabra_v = " " + palabra_v + " "
			if palabra_v.lower() in str(contenido_a).lower():
				self.tmp_diccionario["ioc_anomalo"]["valores"].append(palabra_v)
				contador_venta += 1

		for palabra_a in anomalo:
			palabra_a = " " + palabra_a + " "
			if palabra_a.lower() in str(contenido_a).lower():
				self.tmp_diccionario["ioc_anomalo"]["valores"].append(palabra_a)
				contador_anomalo += 1

		if contador_venta >= 3 and contador_anomalo >= 2:
			self.ioc_anomalo = True
			self.tmp_diccionario["ioc_anomalo"] = self.ioc_anomalo

	def ioc_cryptominer(self):
		'''
		Método que realiza la detección de algún minador en el código de la página
		'''
		print("IOC Cripto")
		contenido_analisis = self.util.obtener_contenido_html(self.sitio)
		ruta = path.abspath(path.dirname(__file__)) + "/config/config_ioc.json"
		with open(ruta,"r") as ci:
			diccionarios = json.load(ci)
		ci.close()
		contador_miner = 0 
		enlaces_crypto = diccionarios["minador"]["enlaces"]
		for script in contenido_analisis.findAll('script'):
			source = script.get('src')
			if source != None:
				for link in enlaces_crypto:
					if link in source:
						contador_miner += 1
						self.tmp_diccionario["ioc_cryptominer"]["valores"].append(link)

		if contador_miner > 0: 
			self.ioc_miner = True
			self.tmp_diccionario["ioc_cryptominer"] = self.ioc_miner

	def ioc_webshell(self):
		'''
		Método que realiza la detección de algún webshell, por medio de peticiones en la página
		'''
		print("IOC Web shell")
		ruta = path.abspath(path.dirname(__file__)) + "/config/config_ioc.json"
		with open(ruta,"r") as ci:
			diccionario = json.load(ci)
		ci.close()
		contador_webshell = 0
		webshell = diccionario["webshell"]["argumentos"]
		comandos = diccionario["webshell"]["comandos"]
		for webs in webshell:
			for comando in comandos:
				comando = comando.replace(" ","+")
				parametro = webs + comando
				url = self.completa_url(parametro,self.sitio)
				respuesta = self.util.get_peticion(url)
				if respuesta != "":
					if respuesta.status_code == 200:
						contenido_analizar = self.util.obtener_contenido_html(url)
						regex = ".*:.*:[0-9]*:[0-9]*:.*:.*:.*"
						if re.search(regex,str(contenido_analizar)) != None:
							self.tmp_diccionario["ioc_webshell"]["valores"].append(url)
							contador_webshell += 1

		if contador_webshell > 0:
			self.webshell_ioc = True
			self.tmp_diccionario["ioc_webshell"] = self.webshell_ioc

	def ioc_ejecutables(self):
		'''
		Método que realiza la detección de ejecutables en el código funte
		'''
		print("IOC Ejecutable")
		ruta = path.abspath(path.dirname(__file__)) + "/config/config_ioc.json"
		with open(ruta,"r") as ci:
			diccionario = json.load(ci)
		ci.close()
		ejecutables = diccionario["ejecutables"]
		contador_ejecutable = 0
		contenido = self.util.obtener_contenido_html(self.sitio)
		for exe in ejecutables:
			if exe in contenido:
				self.tmp_diccionario["ioc_ejecutables"]["valores"].append(exe)
				contador_ejecutable += 1

		if contador_ejecutable > 0:
			self.ejecutable_ioc = True
			self.tmp_diccionario["ioc_ejecutables"] = self.ejecutable_ioc

				
	def completa_url(self,linea,url):
		'''
		Método que completa la url del sitio con los recursos a solicitar
		'''
		link = ""
		if url.endswith("/") and linea.startswith("/"):
			link = url + linea[1:]
		elif url.endswith("/") and not(linea.startswith("/")):
			link = url + linea
		elif not(url.endswith("/")) and linea.startswith("/"):
			link = url + linea
		else:
			link = url + "/" + linea
		return link
				
class Obtencion_informacion():
	'''
	Clase que obtiene la información general de los sitios
	Atibutos:
		redireccionamiento:bool
			Contiene la decisión de seguir el redireccionamiento
		sitio:string
			URL del sitio
		lista_negra:list
			Lista de urls en las cuales no se van a investigar
		tmp_diccionario:dict
			Diccionario que contendrá toda la información del cms que se recabe del sitio
		json_información:dict
			Variable que contiene la información final del sitio
	'''


	def __init__(self, sitio, cookie, lista_negra,redireccionamiento):
		'''
		Inicialización de atributos
		'''
		self.redireccionamiento  = redireccionamiento
		self.lista_negra = lista_negra
		self.sitio = sitio
		self.url_without_file()
		self.tmp_diccionario = {}
		self.json_informacion = {}
		self.paginas = []
		self.paginas.append(self.sitio)
		self.util = Utilerias(cookie, self.redireccionamiento)
		self.cookie = cookie
		self.menu()

	def url_without_file(self):
		'''
		Método que obtiene la url del sitio
		'''
		parsed = urlparse(self.sitio)
		file = parsed.path[parsed.path.rfind("/"):]
		if "." in file:
			self.sitio = parsed.scheme + "://" + parsed.netloc + parsed.path[:parsed.path.rfind("/")+1]
		else:
			self.sitio = parsed.scheme + "://" + parsed.netloc + parsed.path

	def carga_configuracion(self):
		'''
		Método que carga la configuración general de cada uno de los sitio
		Retorna:
			lenguajes_configuracion: list
				Lista de leaguajes de programación en páginas web
			frameworks_configuracion: list
				Lista de frameworks de programación en páginas web
			librerias_configuracion: list
				Lista de librerias de programación en páginas web
		'''
		ruta = path.abspath(path.dirname(__file__))
		ruta += "/config/config_general.json"
		f = open(ruta,"r")
		datos = json.load(f)
		f.close()
		self.leguajes_configuracion = datos["lenguajes"]
		self.frameworks_configuracion = datos["frameworks"]
		self.librerias_configuracion = datos["librerias"]
		
	def get_version_server(self):
		'''
		Método que obtiene la versión del servidor
		Agrega la versión del servisor al diccionario temporal tmp_diccionario
		'''
		print("Wap")
		tmp_dic = {}
		wappalyzer = Wappalyzer.latest()
		error = 0
		while True:
			try:
				webpage = WebPage.new_from_url(self.sitio,verify=False)
				print("Wap Falló :CCC")
				break
			except:
				if error < 5:
					error += 1
				else:
					error = 0
					break

		tmp = wappalyzer.analyze_with_versions_and_categories(webpage)
		for llave,valor in tmp.items():
			for llave2,valor2 in valor.items():
				if llave2 == "categories" and valor2[0] == "Web servers":
					tmp_dic["nombre"] = llave
					try:
						tmp_dic["version"] = valor["versions"][0]
					except:
						tmp_dic["version"] = ""
		self.tmp_diccionario['servidor'] = tmp_dic
		return self.tmp_diccionario

	def get_headers(self):
		'''
		Método que obtiene los headers de seguridad del sitio
		'''
		print("Headers")
		json_headers = {}
		self.headers = []
		ruta = path.abspath(path.dirname(__file__)) + "/shcheck.py"
		comando = "python3 " + ruta + " -d -j " + self.sitio
		args = shlex.split(comando)
		try:
			tmp_headers_json = json.loads(subprocess.run(args, stdout=subprocess.PIPE, text=True).stdout)
		except:
			self.tmp_diccionario["headers"] = []
			return self.tmp_diccionario
		try:
			tmp_headers = tmp_headers_json[self.sitio]
		except:
			tmp_keys = list(tmp_headers_json.keys())
			tmp_sitio = tmp_keys[0]
			tmp_headers = tmp_headers_json[tmp_sitio]
		self.headers_dic = tmp_headers['present']
		for llave, valor in self.headers_dic.items():
			header = llave + " - " + valor
			self.headers.append(header)
		self.tmp_diccionario["headers"] = self.headers
		return self.tmp_diccionario

	def get_cifrados(self):
		'''
		Método ue obtiene los cifrados y su interpretación 
		'''
		print("Cifrados")
		cifrados = {}
		tmp_cifrado = []
		if os.path.exists("salida_ssl.json"):
			subprocess.run(["rm","salida_ssl.json"])
		if self.sitio.startswith("https"):
			ruta = path.abspath(path.dirname(__file__)) + "/config/config_general.json"
			with open(ruta,"r") as cg:
				configuracion = json.load(cg)

			comando = "testssl -E --parallel --sneaky --jsonfile salida_ssl.json " + self.sitio
			args = shlex.split(comando)
			self.cifrados = subprocess.run(args, stdout=subprocess.PIPE, text=True).stdout
			try:
				with open("salida_ssl.json","r") as c:
					datos = json.load(c)
				subprocess.run(["rm","salida_ssl.json"])
				for dato in datos:
					for llave,valor in dato.items():
						if llave == "finding":
							if ("TLS" in valor) or ("SSL" in valor):
								for cifrado,interprete in configuracion["cifrados"].items():
									if cifrado in valor:
										tmp_cifrado = valor.split()
										if "TLS" in tmp_cifrado[0]:
											nombre_cifrado = tmp_cifrado[0] + tmp_cifrado[1] + " - " + tmp_cifrado[-1]
											nombre_cifrado = nombre_cifrado.replace(".","_")
											cifrados[nombre_cifrado] = interprete
											
										else:
											nombre_cifrado = tmp_cifrado[0] + tmp_cifrado[1] + " - " + tmp_cifrado[-1]
											nombre_cifrado = nombre_cifrado.replace(".","_")
											cifrados[tmp_cifrado[0] + " - " + tmp_cifrado[-1]] = interprete
				self.tmp_diccionario["cifrados"] = cifrados
			except:
				self.tmp_diccionario["cifrados"] = {}
		else:
			self.tmp_diccionario["cifrados"] = {}
		return self.tmp_diccionario

	def web_href(self,url):
		'''
		Método que obtiene todas el contenido de las eqtiquetas href
		'''
		dominio = urlparse(url).netloc

		s = self.util.obtener_contenido_html(self.sitio)
		if s != "":
			for link in s.findAll('a'):
				tet_2 = link.get('href')
				if tet_2 != None:
					href = urlparse(tet_2)
					href_dominio = href.netloc

					if href_dominio == "" or href_dominio == dominio:
						url_final = urljoin(url, tet_2.strip())

						if not(url_final in self.paginas) and url_final.startswith("http"):
							print(url_final)
							self.paginas.append(url_final)

	def web_frame(self,url):
		'''
		Método que obtiene las etiquetas iframe
		Parametros:
			url: string
				url del sitio
		'''
		dominio = urlparse(url).netloc

		s = self.util.obtener_contenido_html(self.sitio)
		if s != "":
			for link in s.findAll('iframe'):
				tet_2 = link.get('src')
				if tet_2 != None:
					href = urlparse(tet_2)
					href_dominio = href.netloc

					if href_dominio == "" or href_dominio == dominio:
						url_final = urljoin(url, tet_2.strip())

						if not(url_final in self.paginas) and url_final.startswith("http"):
							print(url_final)
							self.paginas.append(url_final)

	def valida_link(self,linea,url):
		link = ""
		try:
			linea = linea.split()[1]
		except:
			linea = linea
		if url.endswith("/") and linea.startswith("/"):
			link = url + linea[1:]
		elif url.endswith("/") and not(linea.startswith("/")):
			link = url + linea
		elif not(url.endswith("/")) and linea.startswith("/"):
			link = url + linea
		else:
			link = url + "/" + linea
		return link

	def obtener_root(self):
		'''
		Método que obtiene el la raiz del sitio a analizar
		Retorna:
			resultado:string
				Ls url raiz del sitio
		'''
		parse_uri = urlparse(self.sitio)
		resultado = '{uri.scheme}://{uri.netloc}/'.format(uri=parse_uri)
		return resultado

	def get_robots(self,url):
		'''
		Método que obtiene las urls, del archivo robots
		Parametros:
			url:string
				url raiz
		Retorna:
			robot_parser:object
				Objeto de tipo robots que contiene la información del archivo robots.txt
		'''
		self.robot_parser = RobotFileParser()
		try:
			self.robot_parser.set_url(f'{url}robots.txt')
			self.robot_parser.read()
		except:
			self.robot_parser = None
		return self.robot_parser

	def get_paginas(self):
		'''
		Método que obtiene el listdo de las páginas que encuentra
		'''
		print("Paginas")
		link = ""
		tmp_url = self.obtener_root()
		self.get_robots(tmp_url)
		if self.robot_parser:
			for linea in str(self.robot_parser).split("\n"):
				if not("%2A" in linea) and not("User" in linea):
					link = self.valida_link(linea,tmp_url)
					if not(link in self.paginas) and not(link in self.lista_negra):
						self.paginas.append(link)

		paginas_diferentes = []
		for pagina in self.paginas:
			if not pagina.startswith(self.sitio):
				paginas_diferentes.append(pagina)
		
		try:
			for pagina in paginas_diferentes:
				self.paginas.remove(pagina)
		except:
			pass

		paginas_totales = self.paginas.copy()

		for pagina in paginas_totales:
			if pagina not in self.lista_negra:
				self.web_href(pagina)
				self.web_frame(pagina)
				self.tmp_diccionario["paginas"] = [ {"pagina":page} for page in self.paginas if page not in self.lista_negra]
		
		return self.tmp_diccionario

	def get_lenguajes(self):
		'''
		Método que obtiene los leguajes que utiliza la página
		'''
		print("Lenguajes")
		lenguajes = []
		tmp_leng = {}
		resultado = self.get_peticion_w()
		if resultado != "":
			for lenguaje in self.leguajes_configuracion:
				lenguaje = lenguaje.rstrip('\n')
				for llave,valor in resultado.items():
					if lenguaje.lower() in llave.lower():
						tmp_leng = {}
						tmp_leng["nombre"] = llave
						for llave2, valor2 in valor.items():
							if llave2 == "versions":
								try:
									tmp_leng["version"] = valor2
								except:
									tmp_leng["version"] = []
						lenguajes.append(tmp_leng)
		self.tmp_diccionario["lenguajes"] = lenguajes
		return self.tmp_diccionario

	def get_frameworks(self):
		'''
		Método que obtiene los framework, que se ocuparon en el sitio
		'''
		print("Frameworks")
		frameworks = []
		tmp_frame = {}
		resultado = self.get_peticion_w()
		if resultado != "":
			for frame in self.frameworks_configuracion:
				frame = frame.rstrip('\n')
				for llave,valor in resultado.items():
					if frame.lower() in llave.lower():
						tmp_frame = {}
						tmp_frame["nombre"] = llave
						for llave2, valor2 in valor.items():
							if llave2 == "versions":
								try:
									tmp_frame["version"] = valor2
								except:
									tmp_frame["version"] = []
						frameworks.append(tmp_frame)
		self.tmp_diccionario["frameworks"] = frameworks
		return self.tmp_diccionario

	def get_librerias(self):
		'''
		Método que obtiene la lirerias que son ocupadas en el sitio
		'''
		print("Librerías")
		librerias = []
		tmp_libreria = {}
		tmp_total = []
		resultado  = self.get_peticion_w()
		if resultado != "":
			for libreria in self.librerias_configuracion:
				libreria = libreria.rstrip('\n')
				for llave, valor in resultado.items():
					if libreria.lower() in llave.lower():
						tmp_libreria = {}
						tmp_libreria["nombre"] = llave
						for llave2, valor2 in valor.items():
							if llave2 == "versions":
								try:
									tmp_libreria["version"] = valor2
								except:
									tmp_libreria["version"] = []
						librerias.append(tmp_libreria)
			try:
				tmp_total = self.tmp_diccionario["librerias"] + librerias
				self.tmp_diccionario["librerias"] = tmp_total
			except:
				self.tmp_diccionario["librerias"] = librerias
		else:
			self.tmp_diccionario["librerias"] = []
		return self.tmp_diccionario

	def get_peticion_w(self):
		'''
		Método que realiza la petición por medio del modulo de wappalyzer
		'''
		try:
			wappalyzer = Wappalyzer.latest()
			webpage = WebPage.new_from_url(self.sitio,verify=False)
			return wappalyzer.analyze_with_versions_and_categories(webpage)
		except:
			return ""

	def inicializa_diccionario(self):
		self.json_informacion = {'servidor':{}, 'headers':[], 'cifrados':{}, 'lenguajes':[], 'frameworks':[], 'paginas':[], 'cms':{}, 'plugins':[],
								'librerias':[], 'archivos':[], 'vulnerabilidades':[], 'cifrados':{}, 'ioc_anomalo':False, 'ioc_webshell':False,
								'ioc_cryptominer':False, 'ioc_ejecutables':False}

	def menu(self):
		'''
		Método que realiza la validción del cms y contiene la secuencia y creación de objetos,
		para a detección de la información correspondientes
		'''
		self.inicializa_diccionario()
		self.carga_configuracion()
		self.get_version_server()
		self.get_headers()
		self.get_cifrados()
		self.get_lenguajes()
		self.get_frameworks()
		self.get_paginas()
		self.paginas = set(self.paginas)
		detected_cms = None
		detect_root = None
		detect_list = ["Drupal","Moodle","Joomla","Wordpress"]

		for cms_key in detect_list:
			if "Drupal" == cms_key:
				r_objeto = Drupal(self.sitio,self.cookie, self.redireccionamiento)
			elif "Moodle" == cms_key:
				r_objeto = Moodle(self.sitio,self.cookie, self.redireccionamiento)
			elif "Joomla" == cms_key:
				r_objeto = Joomla(self.sitio,self.cookie, self.redireccionamiento)
			elif "Wordpress" == cms_key:
				r_objeto = Wordpress(self.sitio,self.cookie, self.redireccionamiento)
			deteccion_cms = r_objeto.detect_cms()
			if deteccion_cms:
				break
		if deteccion_cms:
			if deteccion_cms == 'drupal':
				print("Drupal")
				r_objeto.inicio_drupal(deteccion_cms,self.tmp_diccionario)
			elif deteccion_cms == 'joomla':
				print("Joomla")
				r_objeto.inicio_joomla(deteccion_cms,self.tmp_diccionario)
			elif deteccion_cms == 'moodle':
				print("Moodle")
				r_objeto.inicio_moodle(deteccion_cms,self.tmp_diccionario)
			elif deteccion_cms == 'wordpress':
				print("Wordpress")
				r_objeto.inicio_wordpress(deteccion_cms,self.tmp_diccionario)
		else:
			self.tmp_diccionario["cms"] = {}
			self.tmp_diccionario["plugins"] = []
			self.tmp_diccionario["archivos"] = []
			self.tmp_diccionario["vulnerabilidades"] = []
		self.get_librerias()
		Obtener_IOC(self.sitio,self.cookie, self.tmp_diccionario,self.redireccionamiento)
		self.json_informacion = self.tmp_diccionario
		print(self.json_informacion)

	def get_json_informacion(self):
		return self.json_informacion

def main():
	Obtencion_informacion()

#main()

def execute(sitio, cookie, lista_negra, redireccionamiento):
	analisis = Obtencion_informacion(sitio, cookie, lista_negra, redireccionamiento)
	return analisis.get_json_informacion()