from pymongo import MongoClient, errors
from modules import strings
from os import path

class Conector():
    def __init__(self):        
        self.conexion = MongoClient(strings.MONGO_URI)
        self.base_datos = self.conexion[strings.BASE_DATOS]
        if self.conexion_estado() == False:
            print("Error: No se logró conectar a la Base de datos")

    def set_conexion(self):
        self.conexion = MongoClient(strings.MONGO_URI)
    
    def set_base_datos(self):
        self.base_datos = self.conexion[strings.BASE_DATOS]

    def get_conexion(self):
        return self.conexion_base_datos

    def exploit_insertar_datos(self,json_cargar_datos):
        coleccion_exploits = self.base_datos[strings.COLECCION_EXPLOITS]
        coleccion_exploits.insert_one(json_cargar_datos)

    def exploit_consulta_nombres(self):
        with self.conexion.start_session() as sesion:
            with sesion.start_transaction():
                nombres_iterados = {"exploits":[]}
                coleccion_exploits = self.base_datos[strings.COLECCION_EXPLOITS]
                nombres = coleccion_exploits.find({},{"nombre":1})
                #{'_id': ObjectId('600bc3e28aaee9e59b5dbab8'), 'nombre': 'pruebap.py'}
                for nombre in nombres:
                    nombres_iterados["exploits"].append(nombre)
                return nombres_iterados

    def exploit_consulta_registro(self,nombre):
        with self.conexion.start_session() as sesion:
            with sesion.start_transaction():
                coleccion_exploits = self.base_datos[strings.COLECCION_EXPLOITS]
                registro = coleccion_exploits.find_one({"nombre":nombre})
                #{'_id': ObjectId('600ca7cea3005813de0d69dd'), 'nomnbre': 'exploit1.py', 'ruta': '/home/kali/Proyectos/proyecto_final_pbsi/modules/exploits', 'software': 'Javascript', 'biblioteca': 'Math', 'gestor_contenido': ''}
                return registro

    def exploit_actualizar_datos(self,json_cargar_datos):
        with self.conexion.start_session() as sesion:
            with sesion.start_transaction():
                coleccion_exploits = self.base_datos[strings.COLECCION_EXPLOITS]
                coleccion_exploits.update_one({"nombre":json_cargar_datos["nombre"]},{"$set":{
                    "nombre":json_cargar_datos["nombre"],
                    "ruta":json_cargar_datos["ruta"],
                    "software":json_cargar_datos["software"],
                    "biblioteca":json_cargar_datos["biblioteca"],
                    "gestor_contenido":json_cargar_datos["gestor_contenido"]}})

    def exploit_buscar_software(self, software):
        with self.conexion.start_session() as sesion:
            with sesion.start_transaction():
                softwares_iterados = {"exploits":[]}
                coleccion_exploits = self.base_datos[strings.COLECCION_EXPLOITS]
                softwares = coleccion_exploits.find({"software":software})
                for software in softwares:
                    lenguaje = self.definir_lenguaje(software["nombre"])
                    if lenguaje == "error":
                        lenguaje = "error"
                    ruta = software["ruta"] + "/" + software["nombre"]
                    if not path.exists(ruta):
                        ruta = "error"
                    softwares_iterados["exploits"].append({"ruta":ruta,"lenguaje":lenguaje})
                return softwares_iterados

    def exploit_buscar_bibliotecas(self, biblioteca):
        with self.conexion.start_session() as sesion:
            with sesion.start_transaction():
                bibliotecas_iterados = {"exploits":[]}
                coleccion_exploits = self.base_datos[strings.COLECCION_EXPLOITS]
                bibliotecas = coleccion_exploits.find({"biblioteca":biblioteca})
                for biblioteca in bibliotecas:
                    lenguaje = self.definir_lenguaje(biblioteca["nombre"])
                    if lenguaje == "error":
                        lenguaje = "error"
                    ruta = biblioteca["ruta"] + "/" + biblioteca["nombre"]
                    if not path.exists(ruta):
                        ruta = "error"
                    bibliotecas_iterados["exploits"].append({"ruta":ruta,"lenguaje":lenguaje})
                return bibliotecas_iterados

    def exploit_buscar_gestor_contenido(self, gestor_contenido):
        with self.conexion.start_session() as sesion:
            with sesion.start_transaction():
                gestor_contenidos_iterados = {"exploits":[]}
                coleccion_exploits = self.base_datos[strings.COLECCION_EXPLOITS]
                gestor_contenidos = coleccion_exploits.find({"gestor_contenido":gestor_contenido})
                for gestor_contenido in gestor_contenidos:
                    lenguaje = self.definir_lenguaje(gestor_contenido["nombre"])
                    if lenguaje == "error":
                        lenguaje = "error"
                    ruta = gestor_contenido["ruta"] + "/" + gestor_contenido["nombre"]
                    if not path.exists(ruta):
                        ruta = "error"
                    gestor_contenidos_iterados["exploits"].append({"ruta":ruta,"lenguaje":lenguaje})
                return gestor_contenidos_iterados

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

    def definir_lenguaje(self, exploit):
        extension = exploit.split(".")[1]
        if extension == "py":
            return "python3 "
        elif extension == "sh":
            return ""
        else:
            return "error"

    def exploit_eliminar_base_total(self):
        with self.conexion.start_session() as sesion:
            with sesion.start_transaction():
                coleccion_exploits = self.base_datos[strings.COLECCION_EXPLOITS]
                coleccion_exploits.delete_many({})