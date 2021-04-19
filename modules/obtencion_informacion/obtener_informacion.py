#!/usr/bin/python3
# -*- coding: utf-8 -*-

import json
import random
# from googlesearch import search
from dnsdumpster.DNSDumpsterAPI import DNSDumpsterAPI
# from py_ms_cognitive import PyMsCognitiveWebSearch
import subprocess
import shlex
from urllib.parse import urlsplit
import re
import socket
from fake_useragent import UserAgent
import requests
from bs4 import BeautifulSoup
import time
from IPy import IP
from os import path
from search_engines import Google, Bing
# from stem import Signal
# from stem.control import Controller


class Robtex_informacion():
    '''
        Esta clase contiene métodos o funciones para la obtención de información de la plataforma Robtex
        Atributos:
            base_api_uri: string
                Url base de la página de robtex
            dominio: string
                Dominio del sitio
            ip_address: string
                Dirección ip del sitio
            información_robtex: dict
                Diccionario de información de robtex
    '''
    def __init__(self, dominio, ip_address):
        '''
        Método de iniciación de atributos
        '''
        self.base_api_url = 'https://freeapi.robtex.com/'
        self.dominio = dominio
        self.ip_address = ip_address
        self.informacion_robtex = {}

    def ip_query(self):
        '''
        Método que realiza la petición a la plataforma de Robtex, por medio de la ip
        Retorna: 
            respuesta:
             La respuesta de la petición
        '''
        respuesta = self.get_respuesta(
            self.base_api_url + "ipquery/{}".format(self.ip_address))
        return respuesta

    def pdns_forward(self):
        '''
        Método que realiza la petición a la plataforma de Robtex, por medio de el nombre de dominio
        Retorna: 
            respuesta: La respuesta de la petición
        '''
        respuesta = self.get_respuesta(
            self.base_api_url + "pdns/forward/{}".format(self.dominio))
        return respuesta

    def pdns_reverse(self):
        '''
        Método que realiza la petición a la plataforma de Robtex, para la obtención de información de dns reverse
        Retorna: La respuesta de la petición
        '''
        respuesta = self.get_respuesta(
            self.base_api_url + "pdns/reverse/{}".format(self.ip_address))
        return respuesta

    def get_respuesta(self, api_solicitud):
        '''
        Método que realiza las solicitudes a la plataforma de Robtex por medio del
        de la url, ingresada
        Entrada:
            - api_solicitud: url de solicitud.
        Retorna: Información en formato json, de la solicitud realizada
        '''
        session = requests.session()
        user_agent = UserAgent().random
        respuesta_solicitud = session.get(
            api_solicitud, headers={'User-Agent': user_agent})
        if respuesta_solicitud.ok:
            try:
                respuesta_solicitud.cookies.clear()
                return json.loads(respuesta_solicitud.text)
            except ValueError:
                respuesta_solicitud.cookies.clear()
                return [json.loads(entry) for entry in respuesta_solicitud.text.split("\r\n") if entry != '']
        else:
            respuesta_solicitud.cookies.clear()
            print("{} error retrieving {}: {}".format(
                respuesta_solicitud.status_code, api_solicitud, respuesta_solicitud.text))
            return None

    def clasificacion_registros(self):
        '''
        Método de clasificación de registros, dada la información retornada mediante la solicitud 
        a la plataforma Robtex, por medio de la API
        Retorna: Un diccionario 
            información_robtex :
            Donde las llaves son titulos de la información recabada, y los valores
        la información recobrada.
        '''
        temp_NS = []
        temp_A = []
        temp_MX = []
        forward = self.pdns_forward()
        reverse = self.pdns_reverse()
        ip = self.ip_query()
        
        for fallo in range(6):
            while ip == None:
                time.sleep(180)
                ip = self.ip_query()
                if fallo == 1:
                    break
            while forward == None:
                time.sleep(180)
                forward = self.pdns_forward()
                if fallo == 3:
                    break
            while reverse == None:
                time.sleep(180)
                reverse = self.pdns_reverse()
        
        if ip is not None:
            informacion = {}
            informacion["ip"] = self.ip_address
            informacion["ciudad"] = ip["city"]
            informacion["pais"] = ip["country"]
            informacion["red"] = ip["bgproute"]
            self.informacion_robtex["informacion"] = informacion
        
        if forward is not None or reverse is not None:
            if("list" in str(type(forward))):
                for registro in forward:
                    self.tipos_registros(
                        registro, temp_NS, temp_A, temp_MX, "forward")
            else:
                self.tipos_registros(forward, temp_NS, temp_A, temp_MX, "forward")
            temp_NS = []
            temp_A = []
            temp_MX = []
            if("list" in str(type(reverse))):
                for registro in reverse:
                    self.tipos_registros(
                        registro, temp_NS, temp_A, temp_MX, "reverse")
            else:
                self.tipos_registros(reverse, temp_NS, temp_A, temp_MX, "reverse")
        
        return self.informacion_robtex
        
    def tipos_registros(self, registro, temp_NS, temp_A, temp_MX, tipo_busqueda):
        '''
        Clasificación de registros de dns.
        Entrada:
            - registro: Obtiene el tipo de registro DNS
            - temp_NS: Arreglo, que guarda los registros NS
            - temp_A: Arreglo, que guarda los registros A
            - temp_MX: Arreglo, que guarda los registros MX
            - tipo_busqueda: Tipo de solicitud que se manda a la pltaforma de Robtex
        Agrega llaves y valores al diccionario información_robtex
        '''
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
    '''
    Clase que contiene métodos de busqueda de información
    Atributos:
        json_información: dic
            Información general de recobrada
        sitio: string
            url del sitio
        user_agent: object
            Objeto de la clase UserAgent
        
    '''
    def __init__(self, sitio, parametros):
        '''
        Métodos de inicialización de atributos del objeto que se crea
        '''
        self.json_informacion = {}
        self.sitio = sitio
        self.user_agent = UserAgent()
        self.set_parametros_json()
        self.set_dorks_google()
        self.set_dorks_bing()
        self.set_robtex(parametros)
        self.set_dnsdumpster(parametros)
        self.set_puertos(parametros)
        self.ejecutar()

    def get_fake_user_agent(self):
        '''
        Método que retorna, un diccionario, con un valor de agente de usuario aleatorio
        '''
        return {'User-Agent': self.user_agent.random}

    def set_parametros_json(self):
        '''
        Método de inicialización de variables, para el almacenamiento de la información
        '''
        try:
            self.ip_address = socket.gethostbyname(self.sitio)
        except socket.gaierror:
            self.ip_address = ""

        self.json_informacion["dnsdumpster"] = {"txt": [], "mx": [], "dns": [], "host": [{
            "dominio": "",
            "ip": "",
            "dns_inverso": "",
            "pais": "",
            "cabecera": ""
        }]
        }

        self.json_informacion["robtex"] = {"informacion": {"ip": self.ip_address,
                                                           "ciudad": "NA",
                                                           "pais": "NA",
                                                           "red": "NA"},
                                           "dns_forward": [], "host_forward": [], 
                                           "mx_forward": [], "host_reverse": []}

        self.json_informacion["google"] = {}
        self.json_informacion["bing"] = {}

        self.informacion_ipv4 = {"inicio_bloque": "", "final_bloque": "", "nombre_bloque": "",
                                 "region": "", "pais": "", "fecha_registro": "", "nombre_bloque": "",
                                 "numero_as": "", "bloque_padre": "", "tamaño_bloque": "", "organizacion": "",
                                 "servidor_web": "", "ciudad": "", 'dominios': []
                                 }

    def set_robtex(self, parametros):
        self.opciones_robtex = {}
        if "robtex" in parametros:
            self.opciones_robtex = parametros["robtex"]

    def set_dnsdumpster(self, parametros):
        self.opciones_dnsdumpster = {}
        if "dnsdumpster" in parametros:
            self.opciones_dnsdumpster = parametros["dnsdumpster"]

    def set_puertos(self, parametros):
        self.opciones_puertos = {}
        if "puertos" in parametros:
            self.opciones_puertos = parametros["puertos"]

    def set_dorks_google(self):
        '''
        Método que obtiene los dorks de consulta en google
        Retorna:
            dorks_google:dict
                Diccionario, de consultas en google, con su eqtiqueta
        '''
        self.dorks_google = []
        ruta = path.abspath(path.dirname(__file__))
        ruta += "/informacion.json"
        f = open(ruta)
        archivo_json = json.load(f)
        self.dorks_google = archivo_json["dorks_google"]

    def set_dorks_bing(self):
        '''
        Método que obtiene los dorks de consulta en bing
        Retorna:
            dorks_bing:dict
                Diccionario, de consultas en google, con su eqtiqueta
        '''
        self.dorks_bing = []
        ruta = path.abspath(path.dirname(__file__))
        ruta += "/informacion.json"
        f = open(ruta)
        archivo_json = json.load(f)
        self.dorks_bing = archivo_json["dorks_bing"]

    def get_robtex(self):
        return self.opciones_robtex

    def get_dnsdumpster(self):
        return self.opciones_dnsdumpster

    def get_puertos(self):
        return self.opciones_puertos

    def ejecutar(self):
        '''
        Método de ejecución, de buquedas por cada uno de los metodos
        '''
        if self.ip_address != "" and IP(self.ip_address).iptype() == "PUBLIC":
            self.busqueda_dnsdumpster()
            self.busqueda_robtex()
            self.google()
            self.busqueda_ipvinfo()
            self.bing()
        self.scanner_puertos()

    def google(self):
        '''
            Método de busqueda en google
            Retorna: 
                resultados_finales: dic
                    Los enlaces encontrados en el buscador de google en una lista
		'''
        print("Entra a Google")
        self.json_informacion["google"] = {}
        dork_sites = {}
        resultados_query = []
        resultados_finales = {}
        dork_site = "site:" + self.sitio
        for tag, dork in self.dorks_google.items():
            if not(dork.startswith(('['))):
                dork_final = dork_site + " " + dork
                dork_sites[tag] = dork_final
        for etiqueta, query in dork_sites.items():
            try:
                resultados_query = self.busqueda_g(query)
            except:
                resultados_query = []
            resultados_finales[etiqueta] = resultados_query
            #time.sleep(60)
        self.json_informacion["google"] = resultados_finales

    def busqueda_g(self, query):
        '''
        Método de obtención de resultados (enlaces), dadas las busquedas realizadas
        Retorna: 
            -links: arreglo de enlaces, resultado de las peiticiones hechas en google
        '''
        engine = Google()
        results = engine.search(query)
        links = results.links()
        return links

    def bing(self):
        '''
        Método de busqueda en bing
            resultados_finales:dic
                Resulados de busqueda de información en la plataforma bing
        Agrega los resultados de la busquedas en bing
        '''
        print("Entra a Bing")
        self.json_informacion["bing"] = {}
        dork_sites = {}
        resultados_query = []
        resultados_finales = {}
        dork_site = "site:" + self.sitio + " AND"
        for tag, dork in self.dorks_bing.items():
            if not(dork.startswith(('['))):
                dork_final = dork_site + " " + dork
                dork_sites[tag] = dork_final
        for etiqueta, query in dork_sites.items():
            try:
                resultados_query = self.busqueda_b(query)
            except:
                resultados_query = []
            resultados_finales[etiqueta] = resultados_query
        self.json_informacion["bing"] = resultados_finales

    def busqueda_b(self, query):
        '''
        Método de obtención de resultados (enlaces), dadas las busquedas realizadas
        Retorna: 
            -links: arreglo de enlaces, resultado de las peiticiones hechas en bing
        '''
        engine = Bing()
        results = engine.search(query)
        links = results.links()
        return links

    def busqueda_ipvinfo(self):
        '''
        Método que que realiza la llamada al método de mandando la url
        '''
        ipv4info = "http://ipv4info.com/?act=check&ip=" + self.sitio
        self.ipv_dominio(ipv4info)

    def ipv_dominio(self, url):
        '''
        Método de obtención de información de la pagina de ipv4
        Agrega al atributo json_informacion, la información recolectada de la pagina
        '''
        tmp_titulo = ""
        titulo_convert = ""
        tmp_diccionario = {}
        tmp_dominios = []
        try:
            print(url)
            respuesta = requests.get(url)
            contenido = BeautifulSoup(respuesta.content, "html.parser")
            print(contenido)
        except:
            contenido = None
        contador = 0
        contador_2 = 0
        if contenido != None:
            print("Entra")
            for tr in contenido.findAll('tr'):
                contador += 1
                if contador == 4:
                    for tr_2 in tr.findAll('tr'):
                        for td in tr_2.findAll('td'):
                            contador_2 += 1
                            if contador_2 <= 1:
                                tmp_titulo = td.string
                                titulo_convert = self.convert_titulo(
                                    tmp_titulo)
                            elif tmp_titulo == "End of block" or tmp_titulo == "Block size" or tmp_titulo == "Block start" or tmp_titulo == "Block name" or tmp_titulo == "Region/State" or tmp_titulo == "Country" or tmp_titulo == "Reg. date" or tmp_titulo == "Host name" or tmp_titulo == "Web server":
                                if contador_2 > 1:
                                    if td.string != None or (tmp_titulo == "Country" and td.string == None) or (tmp_titulo == "Block size" and td.string == None):
                                        try:
                                            self.informacion_ipv4[titulo_convert] = td.string.strip(
                                            )
                                        except:
                                            self.informacion_ipv4[titulo_convert] = td.string
                                        if tmp_titulo == "Country":
                                            self.informacion_ipv4[titulo_convert] = td.contents[1].strip(
                                            )
                                        elif tmp_titulo == "Block size":
                                            self.informacion_ipv4[titulo_convert] = td.contents[0].strip(
                                            )
                                    else:
                                        if tmp_titulo == "Host name":
                                            try:
                                                if td.span.string != None:
                                                    self.informacion_ipv4[titulo_convert] = td.span.string
                                                else:
                                                    self.informacion_ipv4[titulo_convert] = ''
                                            except:
                                                self.informacion_ipv4[titulo_convert] = ''
                                        else:
                                            self.informacion_ipv4[titulo_convert] = ''

                            elif tmp_titulo == "AS number" or tmp_titulo == "Parent block" or tmp_titulo == "City" or tmp_titulo == "Organization":
                                for a in td.findAll('a'):
                                    try:
                                        self.informacion_ipv4[titulo_convert] = a.string.strip(
                                        )
                                    except:
                                        self.informacion_ipv4[titulo_convert] = a.string
                            elif tmp_titulo == "Domains":
                                for domain in td.findAll('a'):
                                    if domain.string != None:
                                        tmp_dominios.append(
                                            domain.string.strip())
                                self.informacion_ipv4[titulo_convert] = tmp_dominios
                        contador_2 = 0
        self.json_informacion["ipv4info"] = self.informacion_ipv4

    def convert_titulo(self, titulo):
        '''
        Método que realiza un cambio de idioma a los titulos, de la información recabada
        '''
        if titulo == "Block start":
            return "inicio_bloque"
        elif titulo == "End of block":
            return "final_bloque"
        elif titulo == "Block size":
            return "tamaño_bloque"
        elif titulo == "Block name":
            return "nombre_bloque"
        elif titulo == "AS number":
            return "numero_as"
        elif titulo == "Parent block":
            return "bloque_padre"
        elif titulo == "Organization":
            return "organizacion"
        elif titulo == "Country":
            return "pais"
        elif titulo == "Reg. date":
            return "fecha_registro"
        elif titulo == "Host name":
            return "nombre_host"
        elif titulo == "Domains":
            return "dominios"
        elif titulo == "Region/State":
            return "region"
        elif titulo == "Web server":
            return "servidor_web"
        elif titulo == "City":
            return "ciudad"

    def busqueda_robtex(self):
        '''
        Método de obtención de información de Robtex
        Agrega al diccionario json_información, la información recolectada mediante las solicitudes a la pagina
        '''
        print("Entra a Robtex")
        robtex = Robtex_informacion(self.sitio, self.ip_address)
        robtex_final = robtex.clasificacion_registros()
        self.json_informacion["robtex"] = robtex_final

    def scanner_puertos(self):
        '''
        Método de de escaner de puertos
        Agrega al diccionario json_informacion un diccionario, que contiene los difrentes
        estados de los puestos, con cada uno de los puertos en ese estado.
        '''
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
        comando = "nmap -sV --max-retries 0 --top-ports " + \
            str(valores_puertos["final"]) + " " + self.sitio
        args = shlex.split(comando)
        salida_comando = subprocess.run(
            args, stdout=subprocess.PIPE, text=True)
        separa_salida = salida_comando.stdout.split("\n")
        for linea in separa_salida:
            regex = r"^[0-9]+/(tcp|udp)[ ]*(open|filtered|closed)[ ]*.*"
            patron_version = r"^(\d+\.?\d*)"
            temp_informacion = {}
            if re.match(regex, linea):
                separar_linea = linea.split()
                puerto_protocolo = separar_linea[0].split("/")
                temp_informacion["puerto"] = puerto_protocolo[0]
                temp_informacion["protocolo"] = puerto_protocolo[1]
                temp_informacion["servicio"] = separar_linea[2] + " " + "".join(separar_linea[3:])
                temp_informacion["version"] = "".join(separar_linea[3:])
                # for version in separar_linea[3:]:
                #     version_regex = re.search(patron_version, version)
                #     if version_regex:
                #         temp_informacion["version"] = version_regex.group()
                #         break
                #     else:
                #         temp_informacion["version"] = 0
                if separar_linea[1] == "open":
                    puertos_abiertos.append(temp_informacion)
                    puertos_completos["abiertos"] = puertos_abiertos
                elif ("filtered" in separar_linea[1]):
                    puertos_filtrados.append(temp_informacion)
                    puertos_completos["filtrados"] = puertos_filtrados
                elif separar_linea[1] == "closed":
                    puertos_cerrados.append(temp_informacion)
                    puertos_completos["cerrados"] = puertos_cerrados
        self.json_informacion["puertos"] = puertos_completos

    def busqueda_dnsdumpster(self):
        '''
        Método que realiza la busqueda de información deacuerdo al sitio en la página de
        DNSDumpster
        Agrega al diccionario json_infomacion, la información recolectada de DNSdupster
        '''
        print("Entra a DNSDumpster")
        dns = []
        mx = []
        host = []
        temp_registros = {}
        contador_datos = 0
        informacion_dnsdumpster = {}
        informacion_dnsdumpster["txt"] = []
        informacion_dnsdumpster['dns'] = []
        informacion_dnsdumpster['mx'] = []
        informacion_dnsdumpster['host'] = []
        registros = DNSDumpsterAPI().search(self.sitio)

        if len(registros) != 0:
            registros = registros["dns_records"]
            informacion_dnsdumpster["txt"] = registros["txt"]
            for registro_dns in registros["dns"]:
                dns.append(self.clasificacion_dnsdumspter(
                    registro_dns, temp_registros, contador_datos))
                temp_registros = {}
            informacion_dnsdumpster['dns'] = dns

            for registro_mx in registros["mx"]:
                mx.append(self.clasificacion_dnsdumspter(
                    registro_mx, temp_registros, contador_datos))
                temp_registros = {}
            informacion_dnsdumpster['mx'] = mx

            for registro_host in registros["host"]:
                host.append(self.clasificacion_dnsdumspter(
                    registro_host, temp_registros, contador_datos))
                temp_registros = {}
            informacion_dnsdumpster['host'] = host

        self.json_informacion["dnsdumpster"] = informacion_dnsdumpster

    def clasificacion_dnsdumspter(self, registros_tipos, temp_registros, contador_datos):
        '''
        Método que realiza la clasificación de registros encontrados en la pagina de DNSDumpster
        Entrada:
            -registros_tipos: Contiene todos los registros encontrados
            -temp_registros: Varuable temporal, que contiene la clasificación de los registros
            -contador_datos: Contador de tipos de datos
        Retorna: Un diccionario temp_registros de la clasificación de los datos, acada uno con su 
        '''
        for llave, valor in registros_tipos.items():
            if llave == "domain":
                temp_registros["dominio"] = valor
                contador_datos += 1
            elif llave == "ip":
                temp_registros["ip"] = valor
                contador_datos += 1
            elif llave == "country":
                temp_registros["pais"] = valor
                contador_datos += 1
            elif llave == "reverse_dns":
                temp_registros["dns_inverso"] = valor
                contador_datos += 1
            elif llave == "header":
                temp_registros["cabecera"] = valor
                contador_datos += 1
            if contador_datos == 5:
                return temp_registros
        return temp_registros

def obtener_sitio_dominio(sitio_limpiar):
    '''
    Función que obtiene el nombre de dominio de la url correspondiente
    Retorna la variable site_dominio, contiene el nombre de dominio
    '''
    if not(sitio_limpiar.startswith(('http://', 'https://'))):
        sitio_limpiar = "https://" + sitio_limpiar
    # Extrae el sitio que se quiere buscar
    base_url = urlsplit(sitio_limpiar).netloc
    separar_base = base_url.split(".")
    # Quita el www a un sitio
    if(separar_base[0] == "www"):
        separar_base.pop(0)
    separar_puerto = separar_base[-1].split(":")
    if(re.search("\d+", separar_puerto[-1]) is not None):
        separar_puerto.pop(-1)
    separar_base[-1] = "".join(separar_puerto)
    site_dominio = '.'.join(separar_base)
    return site_dominio


def execute(parametros):
    sitio_limpio = obtener_sitio_dominio(parametros["sitio"])
    informacion = Obtener_informacion(sitio_limpio, parametros)
    return informacion.json_informacion
