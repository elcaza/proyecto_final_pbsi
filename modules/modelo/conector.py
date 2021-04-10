from pymongo import MongoClient, errors
from os import path, pardir
import base64
import json

class Conector():
    '''
        Clase que permite la interaccion entre el manejador Mongo y el servidor web
        
        .........
        Atributos
        ---------
            strings : dict
                diccionario que guarda el archivo strings.json donde contiene las cadenas necesarias para el funcionamiento con el manejador

            conexion : MongoClient
                instancia para iniciar la conexion con el manejador

            base_datos : Database
                conexion con la base de datos a traves de la conexion creada previamente

        Metodos
        -------
            set_conexion():
                crea la conexion con el manejador y la base de datos

            exploit_insertar_datos(json_cargar_datos):
                hace el cambio de documento para guardar el exploit

            exploit_volcado():
                regresa un diccionario de los exploits almacenados

            exploit_consulta_registro(json_nombre):
                regresa el exploit que coincide con el nombre

            exploit_actualizar_registro(json_cargar_datos):
                actualiza en la base de datos los datos del exploit

            exploit_eliminar_registro(json_cargar_datos):
                elimina el exploit

            exploit_buscar_software(json_software, profundidad):
                obtiene todos los software que coincidad con el software dependiendo de su profunidad

            exploit_buscar_cms(json_cms, profundidad):
                obtiene todos las extensiones de cms que coincidad con las extensiones dependiendo de su profunidad

            exploit_buscar_cve(cve):
                obtiene todos los exploits que coincidadn con el CVE

            conexion_estado():
                regresa el estado del servidor

            conexion_reinicio():
                reinicia la conexion con el servidor

            crear_exploits_unicos():
                declara la regla de que los nombres de exploits son unicos

            guardar_analisis(json_recibido):
                guarda el json recibido en el documento de analisis

            obtener_analisis_totales():
                regresa los analisis totales

            obtener_ultima_fecha():
                regresa la fecha del ultimo analisis

            obtener_analisis_generales():
                regresa un diccionario con los nombres de los sitios analizados con su fecha

            obtener_analisis(peticion):
                regresa el analisis completo

    '''
    def __init__(self):       
        self.set_conexion() 
        
        if self.conexion_estado() == False:
            print("Error: No se logró conectar a la Base de datos")
        self.crear_exploits_unicos()

    def set_conexion(self):
        '''
            crea la conexion con el manejador y la base de datos

            abre el archivo strings.json para cargar al atributo strings con los valores de la 
            base de datos y la conexion
        '''
        ruta = path.abspath(path.join(path.dirname(__file__), pardir)) + "/strings.json"
        with open (ruta, "r") as json_strings:
            self.strings = json.load(json_strings)

        self.conexion = MongoClient(self.strings["MONGO_URI"])
        self.base_datos = self.conexion[self.strings["BASE_DATOS"]]
    
########################################################## CREAR EXPLOITS ##########################################################
    def exploit_insertar_datos(self,json_cargar_datos):
        '''
            hace el cambio de documento para guardar el exploit

            Parametros
            ----------
            json_cargar_datos : dict
                contiene los datos del exploit a guardar
        '''
        coleccion_exploits = self.base_datos[self.strings["COLECCION_EXPLOITS"]]
        try:
            coleccion_exploits.insert_one(json_cargar_datos)
        except errors.DuplicateKeyError:
            print("Ya existe un exploit con el mismo nombre")

    def exploit_volcado(self):
        '''
            regresa un diccionario de los exploits almacenados
        '''
        with self.conexion.start_session() as sesion:
            with sesion.start_transaction():
                nombres_iterados = {"exploits":[]}
                coleccion_exploits = self.base_datos[self.strings["COLECCION_EXPLOITS"]]
                nombres = coleccion_exploits.find({},{"exploit":1,"_id":0})
                for nombre in nombres:
                    nombres_iterados["exploits"].append(nombre)
                return nombres_iterados

    def exploit_consulta_registro(self,json_nombre):
        '''
            regresa el exploit que coincide con el nombre

            Parametros
            ----------
            json_nombre : dict
                contiene solo el nombre del exploit a consultar
        '''
        with self.conexion.start_session() as sesion:
            with sesion.start_transaction():
                coleccion_exploits = self.base_datos[self.strings["COLECCION_EXPLOITS"]]
                registro = coleccion_exploits.find_one({"exploit":json_nombre["exploit"]},{"_id":0})
                ruta_total = registro["ruta"] + "/" + registro["exploit"]
                with open(ruta_total,"rb") as archivo:
                    contenido = base64.encodebytes(archivo.read())
                registro["contenido"] = contenido
                registro.pop("ruta")
                if "software_nombre" in registro:
                    registro["software"] = {"software_nombre":registro["software_nombre"], "software_version":registro["software_version"]}
                    registro.pop("software_nombre")
                    registro.pop("software_version")
                elif "cms_nombre" in registro:
                    registro["cms"] = {"cms_nombre":registro["cms_nombre"], "cms_categoria":registro["cms_categoria"],"cms_extension_nombre":registro["cms_extension_nombre"], "cms_extension_version":registro["cms_extension_version"]}
                    registro.pop("cms_nombre")
                    registro.pop("cms_categoria")
                    registro.pop("cms_extension_nombre")
                    registro.pop("cms_extension_version")
                return registro

    def exploit_actualizar_registro(self,json_cargar_datos):
        '''
            actualiza en la base de datos los datos del exploit

            Parametros
            ----------
            json_cargar_datos : dict
                contiene el nombre del exploit y los datos a modificar
        '''
        with self.conexion.start_session() as sesion:
            with sesion.start_transaction():
                coleccion_exploits = self.base_datos[self.strings["COLECCION_EXPLOITS"]]
                coleccion_exploits.update({"exploit":json_cargar_datos["exploit"]},json_cargar_datos)

    def exploit_eliminar_registro(self,json_cargar_datos):
        '''
            elimina el exploit

            Parametros
            ----------
            json_cargar_datos : dict
                contiene el nombre del exploit a eliminar
        '''
        with self.conexion.start_session() as sesion:
            with sesion.start_transaction():
                coleccion_exploits = self.base_datos[self.strings["COLECCION_EXPLOITS"]]
                coleccion_exploits.delete_one({"exploit":json_cargar_datos["exploit"]})

########################################################## CREAR EXPLOITS ##########################################################

########################################################## IDENTIFICACION EXPLOITS ##########################################################

    def exploit_buscar_software(self, json_software, profundidad):
        '''
            obtiene todos los software que coincidad con el software dependiendo de su profunidad

            Parametros
            ----------
            json_software : dict
                contiene el nombre y version del software a buscar

            profunidad : int
                nivel de profundidad
        '''
        print(json_software)
        with self.conexion.start_session() as sesion:
            with sesion.start_transaction():
                softwares_iterados = {"exploits":[]}
                coleccion_exploits = self.base_datos[self.strings["COLECCION_EXPLOITS"]]
                if profundidad == 1:
                    softwares = coleccion_exploits.find({
                                                        "software_nombre":{"$regex":json_software["software_nombre"],"$options":"i"},
                                                        "software_version":json_software["software_version"]
                                                        })
                elif profundidad == 2:
                    softwares = coleccion_exploits.find({
                                                    "software_nombre":{"$regex":json_software["software_nombre"],"$options":"i"},
                                                    "software_version":{"lte":json_software["software_version"]}
                                                    })
                else: 
                    softwares = coleccion_exploits.find({
                                                    "software_nombre":{"$regex":json_software["software_nombre"],"$options":"i"}
                                                    })
                for software in softwares:
                    lenguaje = software["extension"]
                    if lenguaje == "sh":
                        lenguaje = ""
                    else:
                        lenguaje += " "
                    ruta = software["ruta"] + "/" + software["exploit"]
                    if not path.exists(ruta):
                        ruta = "error"
                    softwares_iterados["exploits"].append({"ruta":ruta,"lenguaje":lenguaje})
                return softwares_iterados

    def exploit_buscar_cms(self, json_cms, profundidad):
        '''
            obtiene todos las extensiones de cms que coincidad con las extensiones dependiendo de su profunidad

            Parametros
            ----------
            json_cms : dict
                contiene los valors de nombre del cms, categoria de la extension, nombre de la extension y su 
                respectiva version a buscar

            profundidad : int
                nivel de profunidad
        '''
        with self.conexion.start_session() as sesion:
            with sesion.start_transaction():
                cmss_iterados = {"exploits":[]}
                coleccion_exploits = self.base_datos[self.strings["COLECCION_EXPLOITS"]]
                if profundidad == 1:
                    cmss = coleccion_exploits.find({
                                                        "cms_nombre":{"$regex":json_cms["cms_nombre"],"$options":"i"},
                                                        "cms_categoria":{"$regex":json_cms["cms_categoria"],"$options":"i"},
                                                        "cms_extension_nombre":{"$regex":json_cms["cms_extension_nombre"],"$options":"i"},
                                                        "cms_extension_version":json_cms["cms_extension_version"] 
                                                    })
                elif profundidad == 2:
                    cmss = coleccion_exploits.find({
                                                    "cms_nombre":{"$regex":json_cms["cms_nombre"],"$options":"i"},
                                                    "cms_categoria":{"$regex":json_cms["cms_categoria"],"$options":"i"},
                                                    "cms_extension_nombre":{"$regex":json_cms["cms_extension_nombre"],"$options":"i"},
                                                    "cms_extension_version":{"lte":json_cms["cms_extension_version"]}
                                                    })
                else:
                    cmss = coleccion_exploits.find({
                                                    "cms_nombre":{"$regex":json_cms["cms_nombre"],"$options":"i"},
                                                    "cms_categoria":{"$regex":json_cms["cms_categoria"],"$options":"i"},
                                                    "cms_extension_nombre":{"$regex":".*"},
                                                    })
                for cms in cmss:
                    lenguaje = self.definir_lenguaje(cms["exploit"])
                    lenguaje = cms["extension"]
                    if lenguaje == "sh":
                        lenguaje = ""
                    else:
                        lenguaje += " "
                    ruta = cms["ruta"] + "/" + cms["exploit"]
                    if not path.exists(ruta):
                        ruta = "error"
                    cmss_iterados["exploits"].append({"ruta":ruta,"lenguaje":lenguaje})
                return cmss_iterados

    def exploit_buscar_cve(self, cve):
        '''
            obtiene todos los exploits que coincidadn con el CVE

            Parametros
            ----------
            cve : str
                nombre del cve
        '''
        with self.conexion.start_session() as sesion:
            with sesion.start_transaction():
                cves_iterados = {"exploits":[]}
                coleccion_exploits = self.base_datos[self.strings["COLECCION_EXPLOITS"]]
                cves = coleccion_exploits.find({"cve":{"$regex":cve,"$options":"i"}})
                
                for cve_exploit in cves:
                    lenguaje = cve_exploit["extension"]
                    if lenguaje == "sh":
                        lenguaje = ""
                    else:
                        lenguaje += " "
                    ruta = cve_exploit["ruta"] + "/" + cve_exploit["exploit"]
                    if not path.exists(ruta):
                        ruta = "error"
                    cves_iterados["exploits"].append({"ruta":ruta,"lenguaje":lenguaje})
                return cves_iterados

########################################################## OBTENER EXPLOITS ##########################################################

########################################################## MONITOREO DE CONEXION ##########################################################

    def conexion_estado(self):
        '''
            regresa el estado del servidor
        '''
        try:
            return self.conexion.server_info()
        except errors.ServerSelectionTimeoutError:
            return False
        
    def conexion_reinicio(self):
        '''
            reinicia la conexion con el servidor
        '''
        try:
            self.conexion = MongoClient(self.strings["MONGO_URI"])
            self.base_datos = self.conexion[self.strings["BASE_DATOS"]]
            return True
        except errors.ServerSelectionTimeoutError:
            print("Error: No se logró conectar a la Base de datos")
        return False

########################################################## MONITOREO DE CONEXION ##########################################################

    def crear_exploits_unicos(self):
        ''' 
            declara la regla de que los nombres de exploits son unicos
        '''
        with self.conexion.start_session() as sesion:
            with sesion.start_transaction():
                coleccion_exploits = self.base_datos[self.strings["COLECCION_EXPLOITS"]]
                coleccion_exploits.create_index("exploit", unique = True)


########################################################## PERSISTENCIA ##########################################################
    
    def guardar_analisis(self, json_recibido):
        '''
            guarda el json recibido en el documento de analisis

            Parametros
            ----------
            json_recibido : dict
                contiene el analisis a guardar
        '''
        coleccion_analisis = self.base_datos[self.strings["COLECCION_ANALISIS"]]
        coleccion_analisis.insert_one(json_recibido)

########################################################## CONSULTAS ##########################################################

    def obtener_analisis_totales(self):
        '''
            regresa los analisis totales
        '''
        coleccion_analisis = self.base_datos[self.strings["COLECCION_ANALISIS"]]
        return coleccion_analisis.count_documents({})

    def obtener_ultima_fecha(self):
        '''
            regresa la fecha del ultimo analisis
        '''
        coleccion_analisis = self.base_datos[self.strings["COLECCION_ANALISIS"]]
        resultados = coleccion_analisis.find({},{"fecha":1,"_id":0}).sort("_id",1).limit(1)
        for resultado in resultados:
            return resultado["fecha"]

    def obtener_analisis_generales(self):
        '''
            regresa un diccionario con los nombres de los sitios analizados con su fecha
        '''
        coleccion_analisis = self.base_datos[self.strings["COLECCION_ANALISIS"]]
        resultados = coleccion_analisis.find({},{"sitio":1,"fecha":1,"_id":0})
        analisis = []
        for resultado in resultados:
            analisis.append({"sitio": resultado["sitio"], "fecha":resultado["fecha"]})
        return analisis

    def obtener_analisis(self, peticion):
        '''
            regresa el analisis completo

            Parametros
            ----------
            peticion : dict
                contiene el sitio a buscar con su respectiva fecha
        '''
        sitio = peticion["sitio"]
        fecha = peticion["fecha"]
        coleccion_analisis = self.base_datos[self.strings["COLECCION_ANALISIS"]]
        resultados = coleccion_analisis.find({"sitio":sitio,"fecha":fecha},{"_id":0})
        for resultado in resultados:
            return resultado