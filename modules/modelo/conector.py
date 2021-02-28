from pymongo import MongoClient, errors
from modules import strings
from os import path

class Conector():
    def __init__(self):        
        self.conexion = MongoClient(strings.MONGO_URI)
        self.base_datos = self.conexion[strings.BASE_DATOS]
        if self.conexion_estado() == False:
            print("Error: No se logró conectar a la Base de datos")
        self.crear_exploits_unicos()

    def set_conexion(self):
        self.conexion = MongoClient(strings.MONGO_URI)
    
    def set_base_datos(self):
        self.base_datos = self.conexion[strings.BASE_DATOS]

    def get_conexion(self):
        return self.conexion_base_datos

########################################################## CREAR EXPLOITS ##########################################################
    def exploit_insertar_datos(self,json_cargar_datos):
        coleccion_exploits = self.base_datos[strings.COLECCION_EXPLOITS]
        try:
            coleccion_exploits.insert_one(json_cargar_datos)
        except errors.DuplicateKeyError:
            print("Ya existe un exploit con el mismo nombre")

    def exploit_consulta_nombres(self):
        with self.conexion.start_session() as sesion:
            with sesion.start_transaction():
                nombres_iterados = {"exploits":[]}
                coleccion_exploits = self.base_datos[strings.COLECCION_EXPLOITS]
                nombres = coleccion_exploits.find({},{"exploit":1,"_id":0})
                for nombre in nombres:
                    nombres_iterados["exploits"].append(nombre)
                return nombres_iterados

    def exploit_consulta_registro(self,json_nombre):
        with self.conexion.start_session() as sesion:
            with sesion.start_transaction():
                coleccion_exploits = self.base_datos[strings.COLECCION_EXPLOITS]
                registro = coleccion_exploits.find_one({"exploit":json_nombre["exploit"]},{"_id":0})
                return registro

    def exploit_actualizar_datos(self,json_cargar_datos):
        with self.conexion.start_session() as sesion:
            with sesion.start_transaction():
                coleccion_exploits = self.base_datos[strings.COLECCION_EXPLOITS]
                coleccion_exploits.update({"exploit",json_cargar_datos["exploit"]},json_cargar_datos)

    def exploit_buscar_existencia(self, ruta):
        if not path.exists(ruta):
            return False

########################################################## CREAR EXPLOITS ##########################################################

########################################################## IDENTIFICACION EXPLOITS ##########################################################

    def exploit_buscar_software(self, json_software, profundidad):
        print(json_software)
        with self.conexion.start_session() as sesion:
            with sesion.start_transaction():
                softwares_iterados = {"exploits":[]}
                coleccion_exploits = self.base_datos[strings.COLECCION_EXPLOITS]
                if profundidad == 1:
                    softwares = coleccion_exploits.find({
                                                        "software_nombre":{"$regex":json_software["software_nombre"],"$options":"i"},
                                                        "software_version":json_software["software_version"]})
                elif profundidad == 2:
                    softwares = coleccion_exploits.find({
                                                    "software_nombre":{"$regex":json_software["software_nombre"],"$options":"i"},
                                                    "software_version":{"$regex":json_software["software_version"]+".*","$options":"i"}})
                else: 
                    softwares = coleccion_exploits.find({
                                                    "software_nombre":{"$regex":json_software["software_nombre"],"$options":"i"},
                                                    "software_version":{"$regex":".*","$options":"i"}})
                for software in softwares:
                    lenguaje = self.definir_lenguaje(software["exploit"])
                    if lenguaje == "error":
                        lenguaje = "error"
                    ruta = software["ruta"] + "/" + software["exploit"]
                    if not path.exists(ruta):
                        ruta = "error"
                    softwares_iterados["exploits"].append({"ruta":ruta,"lenguaje":lenguaje})
                return softwares_iterados

    def exploit_buscar_cms(self, json_cms, profundidad):
        with self.conexion.start_session() as sesion:
            with sesion.start_transaction():
                cmss_iterados = {"exploits":[]}
                coleccion_exploits = self.base_datos[strings.COLECCION_EXPLOITS]
                if profundidad == 1:
                    cmss = coleccion_exploits.find({
                                                        "cms_nombre":{"$regex":json_cms["cms_nombre"],"$options":"i"},
                                                        "cms_categoria":{"$regex":json_cms["cms_categoria"],"$options":"i"},
                                                        "cms_extension_nombre":{"$regex":json_cms["cms_extension_nombre"],"$options":"i"},
                                                        "cms_extension_version":{"$regex":json_cms["cms_extension_version"],"$options":"i"}})
                elif profundidad == 2:
                    cmss = coleccion_exploits.find({
                                                    "cms_nombre":{"$regex":json_cms["cms_nombre"],"$options":"i"},
                                                    "cms_categoria":{"$regex":json_cms["cms_categoria"],"$options":"i"},
                                                    "cms_extension_nombre":{"$regex":json_cms["cms_extension_nombre"],"$options":"i"},
                                                    "cms_extension_version":{"$regex":".*"}})
                else:
                    cmss = coleccion_exploits.find({
                                                    "cms_nombre":{"$regex":json_cms["cms_nombre"],"$options":"i"},
                                                    "cms_categoria":{"$regex":json_cms["cms_categoria"],"$options":"i"},
                                                    "cms_extension_nombre":{"$regex":".*"},
                                                    "cms_extension_version":{"$regex":".*"}})
                for cms in cmss:
                    lenguaje = self.definir_lenguaje(cms["exploit"])
                    if lenguaje == "error":
                        lenguaje = "error"
                    ruta = cms["ruta"] + "/" + cms["exploit"]
                    if not path.exists(ruta):
                        ruta = "error"
                    cmss_iterados["exploits"].append({"ruta":ruta,"lenguaje":lenguaje})
                return cmss_iterados

    def exploit_buscar_cve(self, cve):
        with self.conexion.start_session() as sesion:
            with sesion.start_transaction():
                cves_iterados = {"exploits":[]}
                coleccion_exploits = self.base_datos[strings.COLECCION_EXPLOITS]
                cves = coleccion_exploits.find({"cve":{"$regex":cve,"$options":"i"}})
                
                for cve_exploit in cves:
                    lenguaje = self.definir_lenguaje(cve_exploit["exploit"])
                    if lenguaje == "error":
                        lenguaje = "error"
                    ruta = cve_exploit["ruta"] + "/" + cve_exploit["exploit"]
                    if not path.exists(ruta):
                        ruta = "error"
                    cves_iterados["exploits"].append({"ruta":ruta,"lenguaje":lenguaje})
                return cves_iterados

########################################################## OBTENER EXPLOITS ##########################################################

########################################################## MONITOREO DE CONEXION ##########################################################

    def conexion_estado(self):
        try:
            return self.conexion.server_info()
        except errors.ServerSelectionTimeoutError:
            return False
        
    def conexion_reinicio(self):
        try:
            self.conexion = MongoClient(strings.MONGO_URI)
            self.base_datos = self.conexion[strings.BASE_DATOS]
            return True
        except errors.ServerSelectionTimeoutError:
            print("Error: No se logró conectar a la Base de datos")
        return False

########################################################## MONITOREO DE CONEXION ##########################################################

    def definir_lenguaje(self, exploit):
        extension = exploit.split(".")[1]
        if extension == "py":
            return "python3 "
        elif extension == "sh":
            return ""
        elif extension == "rb":
            return "ruby "
        else:
            return "error"

    def exploit_eliminar_base_total(self):
        with self.conexion.start_session() as sesion:
            with sesion.start_transaction():
                coleccion_exploits = self.base_datos[strings.COLECCION_EXPLOITS]
                coleccion_exploits.delete_many({})

    def crear_exploits_unicos(self):
        with self.conexion.start_session() as sesion:
            with sesion.start_transaction():
                coleccion_exploits = self.base_datos[strings.COLECCION_EXPLOITS]
                coleccion_exploits.create_index("exploit", unique = True)


########################################################## PERSISTENCIA ##########################################################
    
    def guardar_analisis(self, json_recibido):
        coleccion_analisis = self.base_datos[strings.COLECCION_ANALISIS]
        coleccion_analisis.insert_one(json_recibido)

########################################################## CONSULTAS ##########################################################

    def obtener_analisis_totales(self):
        coleccion_analisis = self.base_datos[strings.COLECCION_ANALISIS]
        return coleccion_analisis.count_documents({})

    def obtener_ultima_fecha(self):
        coleccion_analisis = self.base_datos[strings.COLECCION_ANALISIS]
        resultados = coleccion_analisis.find({},{"fecha":1,"_id":0}).sort("_id",1).limit(1)
        for resultado in resultados:
            return resultado["fecha"]

    def obtener_analisis_generales(self):
        coleccion_analisis = self.base_datos[strings.COLECCION_ANALISIS]
        resultados = coleccion_analisis.find({},{"sitio":1,"fecha":1,"_id":0})
        analisis = []
        for resultado in resultados:
            analisis.append("Sitio: {0}, Fecha: {1}".format(resultado["sitio"],resultado["fecha"]))
        return analisis

    def obtener_analisis(self, peticion):
        sitio = peticion["sitio"]
        fecha = peticion["fecha"]
        coleccion_analisis = self.base_datos[strings.COLECCION_ANALISIS]
        resultados = coleccion_analisis.find({"sitio":sitio,"fecha":fecha},{"_id":0})
        for resultado in resultados:
            return resultado

    def informacion_sitio(self, sitio):
        coleccion_analisis = self.base_datos[strings.COLECCION_ANALISIS]
        sitio = coleccion_analisis.find_one({"sitio":sitio})
        informacion = sitio["informacion"]
        return informacion

    def analisis_sitio(self, sitio):
        coleccion_analisis = self.base_datos[strings.COLECCION_ANALISIS]
        sitio = coleccion_analisis.find_one({"sitio":sitio})
        analisis = sitio["analisis"]
        return analisis

    def fuzzing_sitio(self, sitio):
        coleccion_analisis = self.base_datos[strings.COLECCION_ANALISIS]
        sitio = coleccion_analisis.find_one({"sitio":sitio})
        fuzzing = sitio["paginas"]
        return fuzzing

    def explotacion_sitio(self, sitio):
        coleccion_analisis = self.base_datos[strings.COLECCION_ANALISIS]
        sitio = coleccion_analisis.find_one({"sitio":sitio})
        explotacion = sitio["explotaciones"]
        return explotacion
