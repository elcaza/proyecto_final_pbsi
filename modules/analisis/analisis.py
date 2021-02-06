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
from os import path

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

class Wordpress():

	def __init__(self,sitio):
		self.util = Utilerias()
		self.sitio = sitio

	def inicio_wordpress(self,deteccion_cms,tmp_diccionario):
		info = self.carga_configuracion()
		tmp_diccionario["Version"] = self.obtener_version_wordpress()

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
					version = expresion_regular("[0-9][0-9|.]*",match)
				else:
					dominio = obtener_dominio(self.sitio)
					for enlace in sel.obtener_enlaces(self.sitio,dominio):
						if self.expresion_regular("\.[png|jpg].*",enlace) == None:
							version = busqueda_tag_meta(enlace)
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
			match = expresion_regular("[0-9].*\"",match)
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
			elif directorio_existente(path.join(self.sitio,"wp-includes")):
				resultado = True
			elif directorio_existente(path.join(self.sitio, "wp-content")):
				resultado = True

		if resultado:
			return "wordpress"

		return None

	def carga_configuracion(self):
		config_file = self.util.obtener_path_file("config/","config_wordpress",".json")
		with open(config_file) as configuracion:
			datos = json.load(configuracion)
			informacion = datos["wordpress"]
			return informacion

class Moodle():
	def __init__(self,sitio):
		self.url = sitio
		self.util = Utilerias()

	def inicio_moodle(self,deteccion_cms,tmp_diccionario):
		info = self.carga_configuracion()
		tmp_diccionario["Version"] = self.detect_version(info["version_file"])

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
			version = "Desconocida"
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


class Drupal():
	def __init__(self,sitio):
		self.url = sitio
		self.util = Utilerias()

	def inicio_drupal(self,deteccion_cms,tmp_diccionario):
		config = self.carga_configuracion()
		tmp_diccionario['Version'] = self.detect_version(config)
		ver = version.strip().split('.')[0]
		modulos = config['directorios'][0][ver][0]['modules']
		archivos = config['directorios'][0]['expuestos']
		#resultados["vulnerabilidades"] = detect_vulnes(self.url,version)
		#resultados["plugins"] = realiza_peticiones(self.url,modulos,"modulos",300)
		#resultados["librerias"] = ["Drupal almacena sus librerias/plugins en /modules, el resultado de estos se presenta en plugins"]
		#resultados["archivos"] = realiza_peticiones(self.url,archivos,"archivos visibles")

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
				print(self.url + archivo)
				respuesta = self.util.get_peticion(self.url + archivo)
				code = str(respuesta.status_code)[0]
				if code != '4' and code != '3':
					if archivo == "CHANGELOG.txt":
						version = " " + respuesta.text.split(',')[0].split(' ')[1]
		if version:
			return version
		return "Desconocida"

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
				#root = get_root(busca)
				return "drupal"
				# if root:
				# 	#return "drupal",root
				# 	return "drupal"
			else:
				print("No es drupal")
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
		html = urlopen(self.url)
		bs_object = bs(html,features="html.parser")
		exp_regular = r'Drupal [7-9].*'
		for tag in bs_object.findAll("meta",{"content":re.compile(exp_regular)}):
			if re.search(exp_regular, str(tag)):
				return True
		return False

class Joomla():
	def __init__(self,sitio):
		self.sitio = sitio
		self.util = Utilerias()

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


class Obtencion_informacion():

	def __init__(self):
		self.sitio = "https://wordpress.com/"
		self.tmp_diccionario = {}
		self.json_informacion = {}
		# self.url_without_file()
		# self.get_version_server()
		# self.get_headers()
		# self.get_cifrados()
		# self.get_robots()
		self.menu()

	def url_without_file(self):
		parsed = urlparse(self.sitio)
		file = parsed.path[parsed.path.rfind("/"):]
		if "." in file:
			self.sitio = parsed.scheme + "://" + parsed.netloc + parsed.path[:parsed.path.rfind("/")+1]
		else:
			self.sitio = parsed.scheme + "://" + parsed.netloc + parsed.path

	def get_version_server(self):
		f = Utilerias()
		self.version = f.get_peticion(self.sitio).headers["Server"]
		self.tmp_diccionario['Servidor'] = self.version
		return self.tmp_diccionario

	def get_headers(self):
		json_headers = {}
		self.headers = []
		comando = "python3 shcheck.py -d -j " + self.sitio
		args = shlex.split(comando)
		tmp_headers = json.loads(subprocess.run(args, stdout=subprocess.PIPE, text=True).stdout)[self.sitio]
		self.headers_dic = tmp_headers['present']
		for llave, valor in self.headers_dic.items():
			header = llave + " - " + valor
			self.headers.append(header)
		self.tmp_diccionario["Headers"] = self.headers
		return self.tmp_diccionario

	def get_cifrados(self):
		if self.sitio.startswith("https"):
			comando = "testssl.sh/testssl.sh -P --parallel --sneaky " + self.sitio
			args = shlex.split(comando)
			self.cifrados = subprocess.run(args, stdout=subprocess.PIPE, text=True).stdout
			print(self.cifrados)
		else:
			self.cifrados = "No tiene ningún protocolo de cifrado"
			print(self.cifrados)

	def get_robots(self):
		self.robot_parser = RobotFileParser()
		try:
			self.robot_parser.set_url(f'{self.sitio}/robots.txt')
			self.robot_parser.read()
		except(URLError):
			self.robot_parser = None
		print(self.robot_parser)

	def menu(self):
		self.get_version_server()
		self.get_headers()
		detected_cms = None
		detect_root = None
		detect_list = ["Drupal","Moodle","Joomla","Wordpress"]
		#try:
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
				self.tmp_diccionario["CMS"] = deteccion_cms
				break
		if deteccion_cms:
			if deteccion_cms == 'drupal':
				r_objeto = Drupal(self.sitio)
				r_objeto.inicio_drupal(deteccion_cms,self.tmp_diccionario)
			elif deteccion_cms == 'joomla':
				r_objeto = Joomla(self.sitio)
				r_objeto.inicio_joomla(deteccion_cms,self.tmp_diccionario)
			elif deteccion_cms == 'moodle':
				r_objeto = Moodle(self.sitio)
				r_objeto.inicio_moodle(deteccion_cms,self.tmp_diccionario)
			elif deteccion_cms == 'wordpress':
				r_objeto = Wordpress(self.sitio)
				r_objeto.inicio_wordpress(deteccion_cms,self.tmp_diccionario)
		self.json_informacion[self.sitio] = self.tmp_diccionario
		print(self.json_informacion)
		#except KeyError as e:
		#	print("No esta soportado para la version")
		#except:
		#	print("No se encontro el cms")


	# def listFD(self):
	# 	page = self.get_peticion().text
	# 	soup = BeautifulSoup(page, 'html.parser')
	# 	return [self.sitio + '/' + node.get('href') for node in soup.find_all('a') if node.get('href')]

	# def list_directory(self):
	# 	for file in self.listFD():
	# 		print(file)

def main():
	Obtencion_informacion()

main()