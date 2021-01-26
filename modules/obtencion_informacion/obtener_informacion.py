#!/usr/bin/python3
#-*- coding: utf-8 -*-

import argparse
import json
import random
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
from stem import Signal
from stem.control import Controller

def parse():
	parser = argparse.ArgumentParser( prog = 'argparse_creando_paser',
										description = 'Este programa recupera información publica',
										epilog = 'desarrollado para el proyecto final del plan de becarios')
	parser.add_argument('-u', action='store', type=str, required=False, help='Sitio a buscar información', dest='url')
	parser.add_argument('-g', action='store_true', help='busqueda de información en GOOGLE', dest='flag_google')
	parser.add_argument('-b', action='store_true', help='busqueda de información en BING', dest='flag_bing')
	parser.add_argument('-r', action='store_true', help='busqueda de información en Robtex', dest='flag_robtex')
	parser.add_argument('-d', action='store_true', help='busqueda de información en DNSDumpster', dest='flag_dnsdumpster')
	parser.add_argument('-i', action='store_true', help='busqueda de información en IPV4Info', dest='flag_ipvinfo')
	parser.add_argument('-s', action='store', type=str, required=False, help='Scanner de puertos rango', dest='rango_puertos')
	parser.add_argument('-t', action='store', type=str, required=False, help='Scanner de puertos top', dest='top_puertos')
	parser.add_argument('-v', action='store_true', help='busqueda de versiones de puertos', dest='version_puertos')
	parser.add_argument('-a', action='store',help='escanear todos los puertos disponibles', dest='puertos_completos')
	return parser.parse_args()

class Robtex_informacion():
	def __init__(self,dominio):
		self.base_api_url = 'https://freeapi.robtex.com/'
		self.dominio = dominio
		self.ip_address = socket.gethostbyname(self.dominio)

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
		renovar_tor_ip()
		session = requests.session()
		session.proxies = {}
		session.proxies['http'] = 'socks5h://127.0.0.1:9050'
		session.proxies['https'] = 'socks5h://127.0.0.1:9050'
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
		informacion_robtex = {}
		temp_NS = []
		temp_A = []
		temp_MX = []
		dns_forward = {}
		dns_reverse = {}
		forward = self.pdns_forward()
		ip = self.ip_query()
		dns_reverse = self.pdns_reverse()
		informacion = {}
		informacion["ip"] = self.ip_address
		informacion["ciudad"] = ip["city"]
		informacion["pais"] = ip["country"]
		informacion["red"] = ip["bgproute"]
		if("list" in str(type(forward))):
			for registro in forward:
				registros_NS,registros_A,registros_MX = self.tipos_registros(registro,temp_NS,temp_A,temp_MX,"forward")
		else:
			registros_NS,registros_A,registros_MX = self.tipos_registros(self.pdns_forward,temp_NS,temp_A,temp_MX,"forward")
		temp_NS = []
		temp_A = []
		temp_MX = []
		if("list" in str(type(dns_reverse))):
			for registro in dns_reverse:
				registros_A_reverse = self.tipos_registros(registro,temp_NS,temp_A,temp_MX,"reverse")
		else:
			registros_A_reverse = self.tipos_registros(dns_reverse,temp_NS,temp_A,temp_MX,"reverse")
		
		informacion_robtex["informacion"] = informacion
		informacion_robtex["dns_forward"] = registros_NS
		informacion_robtex["host_forward"] = registros_A
		informacion_robtex["mx_forward"] = registros_MX
		informacion_robtex["host_reverse"] = registros_A_reverse
		return informacion_robtex

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
			return temp_NS,temp_A,temp_MX
		else:
			return temp_A

# class Resultados_Google():
# 	def __init__(self,term, num_results=10, lang="en"):
#     	user_agent = UserAgent().random

#     def fetch_results(self,search_term, number_results, language_code):
#         escaped_search_term = search_term.replace(' ', '+')

#         google_url = 'https://www.google.com/search?q={}&num={}&hl={}'.format(escaped_search_term, number_results+1,
#                                                                               language_code)
#         response = get(google_url, headers=self.user_agent)
#         response.raise_for_status()

#         return response.text

    # def parse_results(raw_html):
    #     soup = BeautifulSoup(raw_html, 'html.parser')
    #     result_block = soup.find_all('div', attrs={'class': 'g'})
    #     for result in result_block:
    #         link = result.find('a', href=True)
    #         title = result.find('h3')
    #         if link and title:
    #             yield link['href']

    # html = fetch_results(term, num_results, lang)
    # return list(parse_results(html))



class Obtener_informacion():

	def __init__(self,sitio,opciones):
		self.json_informacion = {}
		self.sitio = sitio
		self.opciones = opciones
		self.busqueda_robtex()
		self.busqueda_dnsdumpster()
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
			renovar_tor_ip()
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
		self.json_informacion["Robtex"] = robtex_final


	def scanner_puertos(self):
		print("Entra a Scanner de puertos")
		puertos_completos = {}
		puertos_abiertos = []
		puertos_cerrados = []
		puertos_filtrados = []
		puertos_sin_filtrar = []
		if self.opciones.rango_puertos != None:
			comando = "nmap --max-retries 0 -p " + self.opciones.rango_puertos + " " + self.sitio
		elif self.opciones.top_puertos:
			comando = "nmap --max-retries 0 --top-ports " + self.opciones.top_puertos + " " + self.sitio
		elif self.opciones.puertos_completos:
			comando = "nmap --max-retries 0 " + self.sitio
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
					puertos_completos["open"] = puertos_abiertos
				elif ("filtered" in separar_linea[1]):
					puertos_filtrados.append(temp_informacion)
					puertos_completos["filtrados"] = puertos_filtrados
				elif separar_linea[1] == "closed":
					puertos_cerrados.append(temp_informacion)
					puertos_completos["cerrados"] = puertos_cerrados
				elif sepra_linea[1] == "unfiltered":
					puertos_sin_filtrar.append(temp_informacion)
					puertos_completos["sin_filtrar"] = puertos_sin_filtrar
		self.json_informacion["Puertos"] = puertos_completos

	def busqueda_dnsdumpster(self):
		print("Entra a DNSDumpster")
		informacion_dnsdumpster = {}
		dns = []
		mx = []
		host = []
		temp_registros = {}
		contador_datos = 0
		registros = DNSDumpsterAPI().search(self.sitio)
		registros = registros["dns_records"]
		informacion_dnsdumpster["txt"] = registros["txt"]
		for registro_dns in registros["dns"]:
			for llave,valor in  registro_dns.items():
				if llave == 'domain':
					temp_registros['dominio'] = valor
					contador_datos += 1
				elif llave == 'ip':
					temp_registros['ip'] = valor
					contador_datos += 1
				elif llave == 'country':
					temp_registros['pais'] = valor
					contador_datos += 1
				elif llave == 'reverse_dns':
					temp_registros['dns_inverso'] = valor
					contador_datos += 1
				elif llave == 'header':
					temp_registros['cabecera'] = valor
					contador_datos +=1
				if contador_datos == 5:
					dns.append(temp_registros)
					temp_registros = {}
					contador_datos = 0
		for registro_mx in registros["mx"]:
			for llave,valor in registro_mx.items():
				if llave == 'domain':
					contador_datos += 1
					temp_registros['dominio'] = valor
				elif llave == 'ip':
					contador_datos += 1
					temp_registros['ip'] = valor
				elif llave == 'country':
					contador_datos += 1
					temp_registros['pais'] = valor
				elif llave == 'reverse_dns':
					contador_datos += 1
					temp_registros['dns_inverso'] = valor
				elif llave == 'header':
					contador_datos += 1
					temp_registros['cabecera'] = valor
				if contador_datos == 5:
					mx.append(temp_registros)
					temp_registros = {}
					contador_datos = 0
		for registro_host in registros["host"]:
			for llave,valor in registro_host.items():
				if llave == 'domain':
					contador_datos += 1
					temp_registros['dominio'] = valor
				elif llave == 'ip':
					contador_datos += 1
					temp_registros['ip'] = valor
				elif llave == 'country':
					contador_datos += 1
					temp_registros['pais'] = valor
				elif llave == 'reverse_dns':
					contador_datos += 1
					temp_registros['dns_inverso'] = valor
				elif llave == 'header':
					contador_datos += 1
					temp_registros['cabecera'] = valor
				if contador_datos == 5:
					host.append(temp_registros)
					temp_registros = {}
					contador_datos = 0
		informacion_dnsdumpster['dns'] = dns
		informacion_dnsdumpster['mx'] = mx
		informacion_dnsdumpster['host'] = host
		self.json_informacion["Dnsdumpster"] = informacion_dnsdumpster



def renovar_tor_ip():
	with Controller.from_port(port = 9051) as controller:
		controller.authenticate(password="hola123")
		controller.signal(Signal.NEWNYM)


def obtener_sitio_dominio(sitio_limpiar):
	if not(sitio_limpiar.startswith(('http://','https://'))):
		sitio_limpiar = "https://" + sitio_limpiar
	#Extrae el sitio que se quiere buscar
	base_url = urlsplit(sitio_limpiar).netloc
	separar_base = base_url.split(".")
	#Quita el www a un sitio
	if(separar_base[0] == "www"):
		separar_base.pop(0)
	site_dominio = '.'.join(separar_base)
	return site_dominio


def main():
	opciones = parse()
	sitio_limpio = obtener_sitio_dominio(opciones.url)
	informacion = Obtener_informacion(sitio_limpio,opciones)
	print(informacion.json_informacion)


main()