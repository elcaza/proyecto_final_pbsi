import subprocess
import shlex
import requests
import json
from urllib.parse import urlparse
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

class Utilerias():
	def __init__(self):
		self.user_agent = UserAgent()

	def get_fake_user_agent(self):
		return {'User-Agent': self.user_agent.random}


	def get_peticion(self,sitio):
		if sitio.startswith("https"):
			respuesta = requests.get(sitio,headers=self.get_fake_user_agent(),verify=False)
		else:
			respuesta = requests.get(sitio,headers=self.get_fake_user_agent())
		return respuesta

	def obtener_path_file(self,relative_path,file_name,extension):
		abs_path = pathlib.Path(__file__).parent.absolute()
		return str(abs_path)+"/"+relative_path+file_name+extension

	def directorio_existente(self,sitio,nivel_deep=0):
		existe = 0
		respuesta = self.get_peticion(sitio)
		codigo_estado = -1
		if len(respuesta.history) > 0:
			codigo_estado = respuesta.history[-1].status_code
		if respuesta.status_code == 200 and not (codigo_estado > 301 and codigo_estado <= 310):
			existe = True

		return  existe

	def obtener_contenido_html(self,sitio):
		respuesta = self.get_peticion(sitio)
		return BeautifulSoup(respuesta.content, "html.parser")

	def buscar_archivo_comun(self,lista_urls):
		files_comunes = []
		i = 0
		for url in lista_urls:
			respuesta = self.get_peticion(url)
			if (respuesta.status_code == 200) and self.directorio_existente(url):
				files_comunes.append(url)
			i += 1
		return files_comunes

	def generar_urls(self,sitio,lista_urls):
		urls = []
		for url in lista_urls:
			if sitio[-1] == "/":
				urls.append(sitio + url)
			else:
				urls.append(sitio + "/" + url)
		return urls

	def escaner_cms_vulnes(self,cms,version):
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
		url_cve_mitre = "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword="
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
		abs_path = pathlib.Path(__file__).parent.absolute()
		abs_path = str(abs_path) + "/vulnes_db/" + nombre_db + ".json"
		try:
			with open(abs_path, "w") as db:
				json.dump(vulnes,db)
		except:
			print("Error no se puede abrir el archivo de vulnerabilidades")

	def identificar_vulnerabilidades(self, vulnes_db, regex):
		vulnes_cms = []
		for vulnerabilidad in vulnes_db:
			cve = vulnerabilidad['cve']
			description = vulnerabilidad['description']
			if regex.search(description):
				vulnes_cms.append({"cve":cve,"description":description})
		return vulnes_cms

class Wordpress():

	def __init__(self,sitio):
		self.util = Utilerias()
		self.sitio = sitio

	def inicio_wordpress(self,deteccion_cms,tmp_diccionario):
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
		informacion_recopilada = {}
		for info in wordpress_info:
			if info["type"] == "json":
				respuesta = self.util.get_peticion(path.join(self.sitio,info["resource"]))
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
					#print(self.sitio + archivo)
					respuesta = self.util.get_peticion(path.join(self.sitio,archivo))
					status_code_redirect = -1
					if len(respuesta.history) > 0:
						status_code_redirect = respuesta.history[0].status_code
					if respuesta.status_code == 200 and not (status_code_redirect > 301 and status_code_redirect <= 310):
						archivos_expuestos.append(archivo)
					else:
						respuesta = requests.post(path.join(self.sitio,archivo),headers=self.util.get_fake_user_agent(),verify=False)
						if len(respuesta.history) > 0:
							status_code_redirect = respuesta.history[0].status_code
						if respuesta.status_code == 200 and not (status_code_redirect > 301 and status_code_redirect <= 310):
							archivos_expuestos.append(archivo)
				informacion_recopilada[info["info"]] = archivos_expuestos
		return informacion_recopilada



	def obtener_version_wordpress(self):
		version = self.busqueda_tag_meta()
		if(version=="Desconocida"):
			respuesta = self.util.get_peticion(path.join(self.sitio,"feed"))
			match = self.expresion_regular("[0-9].*</generator",respuesta.text)
			if match != None:
				match = self.expresion_regular("[0-9].*<",match)
				version = match[:-1]
			else:
				respuesta = self.util.get_peticion(path.join(self.sitio,"readme.html"))
				if(match != None):
					version = self.expresion_regular("[0-9][0-9|.]*",match)
				else:
					dominio = self.obtener_dominio(self.sitio)
					for enlace in self.obtener_enlaces(self.sitio,dominio):
						if self.expresion_regular("\.[png|jpg].*",enlace) == None:
							version = self.busqueda_tag_meta(enlace)
							if (version != "Desconocida"):
								break
		return version


	def expresion_regular(self,expresion,contenido):
		match = re.search(expresion,contenido)
		if(match != None):
			return contenido[match.span()[0]:match.span()[1]]
		return None

	def busqueda_tag_meta(self):
		respuesta = self.util.get_peticion(self.sitio)
		match = self.expresion_regular("content=\"[w|W]ord[p|P]ress.*>",respuesta.text)
		if(match != None):
			match = self.expresion_regular("[0-9].*\"",match)
			return match[:-1]
		return "Desconocida"

	def obtener_dominio(self):
		indices = []
		for match in re.finditer("/",self.sitio + "/"):
			indices.append(match.start())
		return self.sitio[indices[1]+1:indices[2]]


	def detect_cms(self):
		resultado = False
		respuesta = self.util.get_peticion(self.sitio)
		if respuesta.headers.get("Link") != None and "wp-json" in respuesta.headers["Link"]:
			resultado = True
		elif respuesta.headers.get("Set-Cookie") != None and re.search(".*[w|W]ord[p|P]ress.*",respuesta.headers["Set-Cookie"]):
			resultado = True
		else:
			respuesta = self.util.get_peticion(path.join(self.sitio,"readme.html"))
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
		config_file = self.util.obtener_path_file("config/","config_wordpress",".json")
		#print(config_file)
		with open(config_file) as configuracion:
			datos = jsmin(configuracion.read())
			config = json.loads(datos)
			informacion = config["wordpress"]
			return informacion

	def obtener_vulnerabilidades(self,version):
		vulnerabilidades = self.util.escaner_cms_vulnes("wordpress",version)
		lista_vulnerabilidades = []
		if (len(vulnerabilidades) != 0):
			for element in vulnerabilidades:
				lista_vulnerabilidades.append(element.get("cve"))
				#lista_vulnerabilidades.append(element.get("description"))
		return lista_vulnerabilidades

class Moodle():
	def __init__(self,sitio):
		self.url = sitio
		self.util = Utilerias()

	def inicio_moodle(self,deteccion_cms,tmp_diccionario):
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
		tmp_libreria = {}
		tmp_version = []
		if self.url[-1] == "/":
			tmp_url = self.url + librerias
		else:
			tmp_url = self.url + "/" + librerias

		respuesta = self.util.get_peticion(tmp_url)
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
		if self.url[-1] == "/":
			temp_url = self.url + version_file
		else:
			temp_url = self.url + "/" + version_file

		respuesta = self.util.get_peticion(temp_url)
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
		cont = 0
		config_moodle = self.carga_configuracion()
		if len(config_moodle["directorios"]) > 10:
			for directorio_root in config_moodle["directorios"]:
				if self.url[-1] =="/":
					temp_url = self.url + directorio_root
				else:
					temp_url = self.url + "/" + directorio_root
				respuesta = self.util.get_peticion(self.url)
				if respuesta.status_code == 200 and self.util.directorio_existente(self.url):
					cont += 1
			if cont > 5:
				respuesta = self.util.get_peticion(self.url)
				if config_moodle["identifier"] in respuesta.text:
					return "moodle"
		return None

	def carga_configuracion(self):
		config_file = self.util.obtener_path_file("config/","config_moodle",".json")
		with open(config_file) as configuracion:
			datos = json.load(configuracion)
			informacion = datos["moodle"]
			return informacion

	def detect_vulnerabilidades(self,version):
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
	def __init__(self,sitio):
		self.url = sitio
		self.util = Utilerias()

	def inicio_drupal(self,deteccion_cms,tmp_diccionario):
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
				code = str(respuesta.status_code)[0]
				if code != '4' and code != '3':
					if archivo == "CHANGELOG.txt":
						version = " " + respuesta.text.split(',')[0].split(' ')[1]
		if version:
			return version
		return ""

	def get_version_wappalyzer(self):
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
		peticiones = 0
		for archivo in archivos:
			respuesta = self.util.get_peticion(self.url + archivo)
			if respuesta.status_code != 404:
				peticiones += 1
		return peticiones if peticiones > 0 else 0


	def detect_cms(self):
		config_drupal = self.carga_configuracion()
		respuesta = self.util.get_peticion(self.url)
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
		gcontext = ssl.SSLContext()
		html = urlopen(self.url,context=gcontext)
		bs_object = bs(html,features="html.parser")
		exp_regular = r'Drupal [7-9].*'
		for tag in bs_object.findAll("meta",{"content":re.compile(exp_regular)}):
			if re.search(exp_regular, str(tag)):
				return True
		return False

	def realiza_peticiones(self,recursos,busqueda,codigo=0):
		result_list = list()
		for recurso in recursos:
			req = self.util.get_peticion(self.url + recurso)
			if busqueda == "modulos":
				if req.status_code not in range(codigo, codigo + 99) and req.status_code != 404:
					result_list.append(recurso)
			elif busqueda == "archivos visibles":
				if req.status_code == 200:
					result_list.append(recurso)
		return result_list

	def detect_vulnerabilidades(self,version):
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
	def __init__(self,sitio):
		self.sitio = sitio
		self.util = Utilerias()

	def inicio_joomla(self,deteccion_cms,tmp_diccionario):
		tmp_cms = {}
		tmp_cms["nombre"] = "joomla"
		tmp_cms["version"] = self.obtener_version_joomla()
		tmp_diccionario["cms"] = tmp_cms
		tmp_diccionario["plugins"] = []
		tmp_diccionario["librerias"] = []
		tmp_diccionario["archivos"] = self.obtener_archivos_joomla(self.util.generar_urls(self.sitio,self.cargar_configuracion()))
		tmp_diccionario["vulnerabilidades"] = self.obtener_vulnerabilidades(tmp_cms["version"])

	def obtener_version_joomla(self):
		soup = self.util.obtener_contenido_html(self.sitio+"README.txt")
		for linea in (soup.text).splitlines():
			regex = re.compile("([Jj]oomla!)*\d*\.\d\s([Vv]ersion)")
			if regex.search(linea):
				break
		version = re.findall("\d+\.\d+",linea)
		return version[0]

	def obtener_archivos_joomla(self,urls):
		archivos_detectados = []
		for archivo in urls:
			respuesta = self.util.get_peticion(archivo)
			if respuesta.status_code == 200:
				archivos_detectados.append(archivo)
		return archivos_detectados

	def detect_cms(self):
		joomla_encontrado = False
		if not joomla_encontrado:
			joomla_encontrado = self.checar_meta_joomla()
		if not joomla_encontrado:
			joomla_encontrado = self.checar_dom_elements()
		if not joomla_encontrado:
			joomla_encontrado = self.checar_administrador_pagina()
		return ("joomla") if joomla_encontrado else (None)

	def checar_meta_joomla(self):
		soup = self.util.obtener_contenido_html(self.sitio)
		return self.buscar_joomla(soup, "meta",{'name':'generator'},"joomla")

	def checar_dom_elements(self):
		soup = self.util.obtener_contenido_html(self.sitio)
		return self.buscar_joomla(soup, "script", {'class':re.compile('(joomla*)')},"joomla")

	def checar_administrador_pagina(self):
		soup = self.util.obtener_contenido_html(self.sitio+"/administrator")
		if (self.buscar_joomla(soup, "img", {'src':re.compile('(joomla*)')}, "joomla") | self.buscar_joomla(soup, "a", {'class':re.compile('(joomla*)')}, "joomla")):
			return True
		else:
			return False

	def buscar_joomla(self,soup,tag,attrs_objeto,if_containts):
		metatags = soup.find_all(tag,attrs=attrs_objeto)
		for tag in metatags:
			if (if_containts in str(tag).lower()):
				return True
		return False

	def cargar_configuracion(self):
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

class Obtencion_informacion():

	def __init__(self, sitio):
		self.sitio = sitio
		self.url_without_file()
		self.tmp_diccionario = {}
		self.json_informacion = {}
		self.paginas = []
		self.paginas.append(self.sitio)
		self.util = Utilerias()
		self.menu()

	def url_without_file(self):
		parsed = urlparse(self.sitio)
		file = parsed.path[parsed.path.rfind("/"):]
		if "." in file:
			self.sitio = parsed.scheme + "://" + parsed.netloc + parsed.path[:parsed.path.rfind("/")+1]
		else:
			self.sitio = parsed.scheme + "://" + parsed.netloc + parsed.path
		print(self.sitio)

	def carga_configuracion(self):
		ruta = path.abspath(path.dirname(__file__))
		ruta += "/config/config_general.json"
		f = open(ruta,"r")
		datos = json.load(f)
		f.close()
		self.leguajes_configuracion = datos["lenguajes"]
		self.frameworks_configuracion = datos["frameworks"]
		self.librerias_configuracion = datos["librerias"]
		
	def get_version_server(self):
		f = Utilerias()
		tmp_dic = {}
		wappalyzer = Wappalyzer.latest()
		while True:
			try:
				webpage = WebPage.new_from_url(self.sitio,verify=False)
				print("Wap Falló :CCC")
				break
			except:
				pass
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
		cifrados = {}
		tmp_cifrado = []
		self.tmp_diccionario["cifrados"] = {}
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
				pass
		return self.tmp_diccionario


	def web(self,url):
		s = self.util.obtener_contenido_html(self.sitio)
		for link in s.findAll('a'):
			tet_2 = link.get('href')
			if tet_2 != None:
				if not(tet_2.startswith("#")):
					if tet_2.startswith(url):
						if not(tet_2 in self.paginas):
							self.paginas.append(tet_2)
					elif not(tet_2.startswith("http")) and not(tet_2.startswith("https")):
						link_2 = self.valida_link(tet_2,url)
						contador = 0
						esta = 0
						for page in self.paginas:
							contador += 1 
							if (contador >= len(self.paginas)) and not(esta > 0):
								self.paginas.append(link_2)
								contador = 0
								esta = 0
							elif tet_2 in page:
								esta += 1
		return self.paginas

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
		return link

	def get_robots(self):
		self.robot_parser = RobotFileParser()
		try:
			self.robot_parser.set_url(f'{self.sitio}robots.txt')
			self.robot_parser.read()
		except:
			self.robot_parser = None
		return self.robot_parser

	def get_paginas(self):
		link = ""
		self.get_robots()
		if self.robot_parser:
			for linea in str(self.robot_parser).split("\n"):
				if not("%2A" in linea) and not("User" in linea):
					link = self.valida_link(linea,self.sitio)
					if not(link in self.paginas):
						self.paginas.append(link)
		for pagina in self.paginas:
			self.web(pagina)
			self.tmp_diccionario["paginas"] = [ {"pagina":page} for page in self.paginas]
		return self.tmp_diccionario


	def get_lenguajes(self):
		lenguajes = []
		tmp_leng = {}
		resultado = self.get_peticion_w()
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
		frameworks = []
		tmp_frame = {}
		resultado = self.get_peticion_w()
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
		librerias = []
		tmp_libreria = {}
		tmp_total = []
		resultado  = self.get_peticion_w()
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
		return self.tmp_diccionario

	def get_peticion_w(self):
		wappalyzer = Wappalyzer.latest()
		webpage = WebPage.new_from_url(self.sitio,verify=False)
		return wappalyzer.analyze_with_versions_and_categories(webpage)

	def menu(self):
		self.carga_configuracion()
		self.get_version_server()
		self.get_headers()
		self.get_cifrados()
		self.get_lenguajes()
		self.get_frameworks()
		self.get_paginas()
		detected_cms = None
		detect_root = None
		detect_list = ["Drupal","Moodle","Joomla","Wordpress"]

		for cms_key in detect_list:
			if "Drupal" == cms_key:
				r_objeto = Drupal(self.sitio)
			elif "Moodle" == cms_key:
				r_objeto = Moodle(self.sitio)
			elif "Joomla" == cms_key:
				r_objeto = Joomla(self.sitio)
			elif "Wordpress" == cms_key:
				r_objeto = Wordpress(self.sitio)
			deteccion_cms = r_objeto.detect_cms()
			if deteccion_cms:
				break
		if deteccion_cms:
			if deteccion_cms == 'drupal':
				r_objeto.inicio_drupal(deteccion_cms,self.tmp_diccionario)
			elif deteccion_cms == 'joomla':
				r_objeto.inicio_joomla(deteccion_cms,self.tmp_diccionario)
			elif deteccion_cms == 'moodle':
				r_objeto.inicio_moodle(deteccion_cms,self.tmp_diccionario)
			elif deteccion_cms == 'wordpress':
				r_objeto.inicio_wordpress(deteccion_cms,self.tmp_diccionario)
		else:
			self.tmp_diccionario["cms"] = {}
			self.tmp_diccionario["plugins"] = []
			self.tmp_diccionario["archivos"] = []
			self.tmp_diccionario["vulnerabilidades"] = []
		self.get_librerias()
		self.json_informacion = self.tmp_diccionario

	def get_json_informacion(self):
		return self.json_informacion

def main():
	Obtencion_informacion()

#main()

def execute(sitio):
	analisis = Obtencion_informacion(sitio)
	return analisis.get_json_informacion()