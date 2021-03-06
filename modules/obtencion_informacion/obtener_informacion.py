#!/usr/bin/python3
#-*- coding: utf-8 -*-

import json
import random
from time import sleep, time
#from googlesearch import search
from dnsdumpster.DNSDumpsterAPI import DNSDumpsterAPI
#from py_ms_cognitive import PyMsCognitiveWebSearch
import subprocess
import shlex
from urllib.parse import urlsplit
import re
import sys
import socket
from fake_useragent import UserAgent
import requests
from bs4 import BeautifulSoup
from IPy import IP
#from stem import Signal
#from stem.control import Controller


class Robtex_informacion():
	def __init__(self,dominio):
		self.base_api_url = 'https://freeapi.robtex.com/'
		self.dominio = dominio
		try:
			self.ip_address = socket.gethostbyname(self.dominio)
		except socket.gaierror:
			self.ip_address = ""
		self.informacion_robtex = {}

	def ip_query(self):
		respuesta = self.get_respuesta(self.base_api_url + "ipquery/{}".format(self.ip_address))
		return respuesta

	def pdns_forward(self):
		respuesta = self.get_respuesta(self.base_api_url + "pdns/forward/{}".format(self.dominio))
		return respuesta

	def pdns_reverse(self):
		respuesta = self.get_respuesta(self.base_api_url + "pdns/reverse/{}".format(self.ip_address))
		return respuesta

	def get_respuesta(self,api_solicitud):
		#renovar_tor_ip()
		session = requests.session()
		#session.proxies = {}
		#session.proxies['http'] = 'socks5h://127.0.0.1:9050'
		#session.proxies['https'] = 'socks5h://127.0.0.1:9050'
		user_agent = UserAgent().random
		respuesta_solicitud = session.get(api_solicitud,headers={'User-Agent':user_agent})
		if respuesta_solicitud.ok:
			try:
				return json.loads(respuesta_solicitud.text)
			except ValueError:
				return [json.loads(entry) for entry in respuesta_solicitud.text.split("\r\n") if entry != '']
		else:
			print("{} error retrieving {}: {}".format(respuesta_solicitud.status_code,api_solicitud,respuesta_solicitud.text))
			return None
	
	def clasificacion_registros(self):
		self.informacion_robtex = {"informacion":{"ip": self.ip_address,
		"ciudad": "NA",
		"pais": "NA",
		"red": "NA"}
		,"dns_forward":[],"host_forward":[],"mx_forward":[],"host_reverse":[]}
		if self.ip_address != "" and IP(self.ip_address).iptype() == "PUBLIC":
			temp_NS = []
			temp_A = []
			temp_MX = []

			forward = self.pdns_forward()
			reverse = self.pdns_reverse()
			ip = self.ip_query()

			while ip == None:
				sleep(180)
				ip = self.ip_query()

			while forward == None:
				sleep(180)
				forward = self.pdns_forward()

			while reverse == None:
				sleep(180)
				reverse = self.pdns_reverse()

			informacion = {}
			informacion["ip"] = self.ip_address
			informacion["ciudad"] = ip["city"]
			informacion["pais"] = ip["country"]
			informacion["red"] = ip["bgproute"]
			self.informacion_robtex["informacion"] = informacion
			if("list" in str(type(forward))):
				for registro in forward:
					self.tipos_registros(registro,temp_NS,temp_A,temp_MX,"forward")
			else:
				self.tipos_registros(forward,temp_NS,temp_A,temp_MX,"forward")
				
			temp_NS = []
			temp_A = []
			temp_MX = []

			if("list" in str(type(reverse))):
				for registro in reverse:
					self.tipos_registros(registro,temp_NS,temp_A,temp_MX,"reverse")
			else:
				self.tipos_registros(reverse,temp_NS,temp_A,temp_MX,"reverse")
		return self.informacion_robtex

	def tipos_registros(self,registro,temp_NS,temp_A,temp_MX,tipo_busqueda):
		temp_informacion = {}
		if ('NS' in registro["rrtype"]):
			temp_informacion["dominio"] = registro['rrname']
			temp_informacion["dns"] = registro['rrdata']
			temp_NS.append(temp_informacion)
		elif ('A' in registro["rrtype"]):
			temp_informacion["dominio"] = registro['rrname']
			temp_informacion["host"] = registro['rrdata']
			temp_A.append(temp_informacion)
		elif ('MX' in registro["rrtype"]):
			temp_informacion["dominio"] = registro['rrname']
			temp_informacion["mx"] = registro['rrdata']
			temp_MX.append(temp_informacion)
		if(tipo_busqueda == "forward"):
			self.informacion_robtex["dns_forward"] = temp_NS
			self.informacion_robtex["host_forward"] = temp_A
			self.informacion_robtex["mx_forward"] = temp_MX
		else:
			self.informacion_robtex["host_reverse"] = temp_A

class Obtener_informacion():

	def __init__(self,sitio,parametros):
		self.json_informacion = {}
		self.sitio = sitio
		self.set_robtex(parametros)
		self.set_dnsdumpster(parametros)
		self.set_puertos(parametros)
		self.ejecutar()

	def set_robtex(self,parametros):
		self.opciones_robtex = {}
		if "robtex" in parametros:
			self.opciones_robtex = parametros["robtex"]

	def set_dnsdumpster(self,parametros):
		self.opciones_dnsdumpster = {}
		if "dnsdumpster" in parametros:
			self.opciones_dnsdumpster = parametros["dnsdumpster"]

	def set_puertos(self,parametros):
		self.opciones_puertos = {}
		if "puertos" in parametros:
			self.opciones_puertos = parametros["puertos"]

	def get_robtex(self):
		return self.opciones_robtex

	def get_dnsdumpster(self):
		return self.opciones_dnsdumpster

	def get_puertos(self):
		return self.opciones_puertos

	def ejecutar(self):

		self.busqueda_dnsdumpster()
		self.busqueda_robtex()
		self.scanner_puertos()

	def busqueda_google(self):
		#print("Entra a google")
		TLD = ["com","com.tw","co.in","be","de","co.uk","co.ma","dz","ru","ca"]
		dork_sites = []
		#dork  agregarse para la busqueda de información
		dorks = open('google_dorks.txt','r')
		dork_add = dorks.readlines()
		dorks.close()
		#Dork de los sitios que se van a recuperar
		dork_site = "site:" + self.sitio
		for dork in dork_add:
			if not(dork.startswith(('['))):
				dork_final = dork_site + " " + dork
				dork_sites.append(dork_final)
		print(dork_sites)
		for query in dork_sites:
			#renovar_tor_ip()
			for result in search(query, num=5, tld=random.choice(TLD)):
				print(result)

	def busqueda_ipvinfo(self):
		api_solicitud = "http://ipv4info.com/api_v1/?key=KEY&type=SUBDOMAINS&value=" + self.sitio + "&page=0"
		respuesta_solicitud = requests.get(api_solicitud)
		print(respuesta_solicitud.text)
	
	def busqueda_robtex(self):
		print("Entra a Robtex")
		robtex = Robtex_informacion(self.sitio)
		robtex_final = robtex.clasificacion_registros()
		self.json_informacion["robtex"] = robtex_final

	def scanner_puertos(self):
		print("Entra a Scanner de puertos")
		puertos_completos = {}
		puertos_completos["abiertos"] = []
		puertos_completos["filtrados"] = []
		puertos_completos["cerrados"] = []
		puertos_abiertos = []
		puertos_cerrados = []
		puertos_filtrados = []
		puertos_sin_filtrar = []
		valores_puertos = self.opciones_puertos
		rango_puertos = str(valores_puertos["inicio"]) + "-" + str(valores_puertos["final"])
		comando = "nmap --max-retries 0 --top-ports " + str(valores_puertos["final"]) + " " + self.sitio
		args = shlex.split(comando)
		salida_comando = subprocess.run(args, stdout=subprocess.PIPE, text=True)
		separa_salida = salida_comando.stdout.split("\n")
		for linea in separa_salida:
			regex = r"^[0-9]+/(tcp|udp)[ ]*(open|filtered|closed)[ ]*.*"
			temp_informacion = {}
			if re.match(regex,linea):
				separar_linea = linea.split()
				puerto_protocolo = separar_linea[0].split("/")
				temp_informacion["puerto"] = puerto_protocolo[0]
				temp_informacion["protocolo"] = puerto_protocolo[1]
				temp_informacion["servicio"] = separar_linea[2]
				if separar_linea[1] == "open":
					puertos_abiertos.append(temp_informacion)
					puertos_completos["abiertos"] = puertos_abiertos
				elif ("filtered" in separar_linea[1]):
					puertos_filtrados.append(temp_informacion)
					puertos_completos["filtrados"] = puertos_filtrados
				elif separar_linea[1] == "closed":
					puertos_cerrados.append(temp_informacion)
					puertos_completos["cerrados"] = puertos_cerrados
				elif separar_linea[1] == "sin_filtrar":
					puertos_sin_filtrar.append(temp_informacion)
					puertos_completos["sin_filtrar"] = puertos_sin_filtrar
		self.json_informacion["puertos"] = puertos_completos

	def busqueda_dnsdumpster(self):
		print("Entra a DNSDumpster")
		informacion_dnsdumpster = {}
		informacion_dnsdumpster["txt"] = []
		informacion_dnsdumpster["mx"] = []
		informacion_dnsdumpster["dns"] = []
		informacion_dnsdumpster["host"] = [{
			"dominio":"",
			"ip":"",
			"dns_inverso":"",
			"pais":"",
			"cabecera":""
		}]
		dns = []
		mx = []
		host = []
		temp_registros = {}
		contador_datos = 0
		try:
			self.ip_address = socket.gethostbyname(self.sitio)
		except socket.gaierror:
			self.ip_address = ""

		if self.ip_address != "" and IP(self.ip_address).iptype() == "PUBLIC":
			registros = DNSDumpsterAPI().search(self.sitio)
			if len(registros) != 0:
				registros = registros["dns_records"]

				informacion_dnsdumpster["txt"] = registros["txt"]
				for registro_dns in registros["dns"]:
					dns.append(self.clasificacion_dnsdumspter(registro_dns,temp_registros,contador_datos))
					temp_registros = {}
				informacion_dnsdumpster['dns'] = dns
				for registro_mx in registros["mx"]:
					mx.append(self.clasificacion_dnsdumspter(registro_mx,temp_registros,contador_datos))
					temp_registros = {}
				informacion_dnsdumpster['mx'] = mx
				for registro_host in registros["host"]:
					host.append(self.clasificacion_dnsdumspter(registro_host,temp_registros,contador_datos))
					temp_registros = {}
				informacion_dnsdumpster['host'] = host
		self.json_informacion["dnsdumpster"] = informacion_dnsdumpster

	def clasificacion_dnsdumspter(self,registros_tipos,temp_registros,contador_datos):
		for llave,valor in registros_tipos.items():
			if llave == "domain":
				temp_registros["dominio"] = valor
				contador_datos += 1
			elif llave == "ip":
				temp_registros["ip"] = valor
				contador_datos += 1
			elif llave == "country":
				temp_registros["pais"] = valor
				contador_datos += 1
			elif llave == "reverse_dns" :
				temp_registros["dns_inverso"] = valor
				contador_datos += 1
			elif llave == "header":
				temp_registros["cabecera"] = valor
				contador_datos += 1
			if contador_datos == 5:
				return temp_registros
		return temp_registros

#def renovar_tor_ip():
#	with Controller.from_port(port = 9051) as controller:
#		controller.authenticate(password="hola123")
#		controller.signal(Signal.NEWNYM)


def obtener_sitio_dominio(sitio_limpiar):
	if not(sitio_limpiar.startswith(('http://','https://'))):
		sitio_limpiar = "https://" + sitio_limpiar
	#Extrae el sitio que se quiere buscar
	base_url = urlsplit(sitio_limpiar).netloc
	separar_base = base_url.split(".")
	#Quita el www a un sitio
	if(separar_base[0] == "www"):
		separar_base.pop(0)
	separar_puerto = separar_base[-1].split(":")
	if( re.search("\d+",separar_puerto[-1]) is not None ):
		separar_puerto.pop(-1)
	separar_base[-1] = "".join(separar_puerto)
	site_dominio = '.'.join(separar_base)
	return site_dominio


def execute(parametros):
	sitio_limpio = obtener_sitio_dominio(parametros["sitio"])
	informacion = Obtener_informacion(sitio_limpio,parametros)
	# with open("reporte_informacion.json","w") as file_informacion:
	# 	json.dump(informacion.json_informacion, file_informacion, indent=4)
	return informacion.json_informacion