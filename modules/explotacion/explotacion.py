from json.decoder import JSONDecodeError
from subprocess import check_output, CalledProcessError, TimeoutExpired
from os import path
import concurrent.futures
from itertools import product
import json

class Explotacion():
    '''
        Clase para copiar los exploits y poderlos modificar de acuerdos las datos recabados del modulo de 
        obtener informacion y analisis

        .........
        Atributos
        ---------
        nombre : str
            nombre del exploit
        
        parametros : dict
            valores que contienen el sitio y puertos

        exploit : dict
            valores que contienen la ruta del exploit junto con su extension 

        resultado : dict
            guarda el resultado de cada ejecucion del exploit

        json_explotacion : dict
            guarda el conjunto de resultados

        producto_nombre : array
            contiene los nombres de los tipos de parametros a iterar

        producto_valor : array
            contiene el conjunto de los valores a iterar en los exploits
            
        Metodos
        -------
        lanzar_exploit():
            se ejecuta por defecto al iniciar el hilo el cual lanza las funciones para extraer el exploit y sus valores para iterar
        
        obtener_producto():
            obtiene todas las posibles combinaciones para modificar los scripts

        arreglo_vacio(arreglo):
            regresa True si tiene una longitud mayor a cero el arreglo

        get_resultado():
            regresa el resultado del exploit

        obtener_nombre():
            regresa el nombre del exploit

        get_json_explotacion():
            regresa el json_explotacion

        set_puertos():
            obtiene de los parametros los puertos a iterar

        set_sitio():
            obtiene el sitio de los parametros
        
        set_cookie():
            obtiene la cookie de los parametros
                
        set_usuarios():
            obtiene los usuarios del archivo usuarios.json

        set_contrasenas():
            obtiene los usuarios del archivo contrasenas.json

        validar_campo(valor):
            valida la existencia del campo en el arreglo de nombres
                
        execute():
            crea los hilos para ejecutar cada exploit y guardarlo en el objeto json_explotacion
            
        modificar_exploit_sitio(exploit, exploit_temporal):
            sustituye todas las cadenas APP_SITIO por el sitio proporcionado

        modificar_exploit_puerto(puerto, exploit, exploit_temporal):
            sustituye todas las cadenas APP_PUERTO por el puerto proporcionado

        modificar_exploit_usuario(usuario, exploit_temporal):
            sustituye todas las cadenas APP_USUARIO por el usuario proporcionado
                
        modificar_exploit_contrasena(contrasena, exploit_temporal):
            sustituye todas las cadenas APP_CONTRASENA por la contrasena proporcionada
                
        modificar_exploit_cookie(cookie, exploit_temporal):
            sustituye todas las cadenas APP_COOKIE por la cookie proporcionada

        crear_copia_temporal(exploit, exploit_temporal):
            crea una copia del exploit a ejecutar

        otorgar_permisos_exploit(exploit_temp):
            da permisos al exploit temporal

        ejecutar_exploit(exploit):
            ejecuta el exploit

        eliminiar_exploit_temporal(exploit_temp):
            elimina el exploit

        limpiar_exploit(exploit, lenguaje):
            obtiene la ruta del exploit temporal y prepara el exploit para ser ejecutado con su extension

        cargar_parametros(puerto, exploit, exploit_temporal):
            funcion que manda a llamar a las funciones para modificar sus parametros

        validar_resultado(resultado):
            valida el resultado al leer el texto provocado por el exploit, si es valido o invalido

    '''
    def __init__(self, parametros, exploits):
        self.parametros = parametros
        self.exploits = exploits
        self.json_explotacion = {"explotaciones":{}}
        self.ruta = path.abspath(path.dirname(__file__))
        self.set_puertos()
        self.set_sitio()
        self.set_cookie()
        self.set_usuarios()
        self.set_contrasenas()
        self.obtener_producto()
        self.execute()
        
    def lanzar_exploit(self, exploit, lenguaje):
        '''
            se ejecuta por defecto al iniciar el hilo el cual lanza las funciones para extraer el exploit y sus valores para iterar

            Parametros
            ----------
            exploit : str
                ruta del exploit
            lenguaje : str
                interprete o ejecutable del exploit
        '''
        resultado = {}
        json_temporal = {}
        exploit_temporal, exploit_preparado = self.limpiar_exploit(exploit, lenguaje)
        for producto in self.producto_valor:
            valor = ",".join(str(dato) for dato in producto[1:])
            self.cargar_parametros(producto, exploit, exploit_temporal)
            self.otorgar_permisos_exploit(exploit_temporal)
            resultado[valor] = self.ejecutar_exploit(exploit_preparado)
            resultado[valor] = self.validar_resultado(resultado[valor])
            self.eliminiar_exploit_temporal(exploit_temporal)
            json_temporal[self.obtener_nombre(exploit)] = resultado
        return json_temporal

    def obtener_producto(self):
        '''
            obtiene todas las posibles combinaciones para modificar los scripts
        '''
        combinaciones = []
        self.producto_nombre = []
        diccionario_combinaciones = {
            "puertos":self.puertos,
            "usuarios":self.usuarios,
            "contrasenas":self.contrasenas,
            "cookie":[self.cookie]
        }
        for valor in diccionario_combinaciones:
            if self.arreglo_vacio(diccionario_combinaciones[valor]):
                combinaciones.append(diccionario_combinaciones[valor])
                self.producto_nombre.append(valor)

        self.producto_valor = list(product(*combinaciones))
    
    def arreglo_vacio(self, arreglo):
        '''
            regresa True si tiene una longitud mayor a cero el arreglo

            Parametros
            ----------
            arreglo : array
        '''
        if len(arreglo) != 0:
            return True
        return False

    def get_resultado(self):
        '''
            regresa el resultado del exploit
        '''
        return self.resultado
    
    def obtener_nombre(self, exploit):
        '''
            regresa el nombre del exploit

            Parametros
            ----------
            exploit : str
                regresa el nombre del exploit
        '''
        nombre = exploit.rsplit("/")[-1].replace(".","_")
        return nombre

    def get_json_explotacion(self):
        '''
            regresa el json_explotacion
        '''
        return self.json_explotacion
    
    def set_puertos(self):
        ''' 
            obtiene de los parametros los puertos a iterar
        '''
        if "puertos" in self.parametros:
            self.puertos = self.parametros["puertos"]
        else:
            self.puertos = []

    def set_sitio(self):
        '''
            obtiene el sitio de los parametros
        '''
        if "sitio" in self.parametros:
            self.sitio = self.parametros["sitio"]
        else:
            self.sitio = ""

    def set_cookie(self):
        '''
            obtiene la cookie de los parametros
        '''
        if "cookie" in self.parametros:
            self.cookie = self.parametros["cookie"]
        else:
            self.cookie = ""

    def set_usuarios(self):
        '''
            obtiene los usuarios del archivo usuarios.json
        '''
        try:
            ruta = "{0}{1}".format(self.ruta,"/usuarios.json")
            with open(ruta,"r") as users:
                self.usuarios = json.load(users)
        except (FileNotFoundError,JSONDecodeError):
            self.usuarios = []

    def set_contrasenas(self):
        '''
            obtiene los usuarios del archivo contrasenas.json
        '''
        try:
            ruta = "{0}{1}".format(self.ruta,"/contrasenas.json")
            with open(ruta,"r") as contras:
                self.contrasenas = json.load(contras)
        except (FileNotFoundError,JSONDecodeError):
            self.contrasenas = []

    def validar_campo(self, valor):
        '''
            valida la existencia del campo en el arreglo de nombres

            Parametros
            ----------
            valor : str
                cadena que sera buscada dentro del arreglo
        '''
        try:
            index = self.producto_nombre.index(valor)
            return index
        except ValueError:
            return False

    def execute(self):
        '''
            crea los hilos para ejecutar cada exploit y guardarlo en el objeto json_explotacion
        '''
        futures = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            for exploit in self.exploits:
                exploit_nombre = exploit["ruta"]
                lenguaje = exploit["lenguaje"]

                futures.append(executor.submit(self.lanzar_exploit, exploit_nombre, lenguaje))
            for future in concurrent.futures.as_completed(futures):
                explotacion = future.result()
                if len(explotacion) != 0:
                    self.json_explotacion["explotaciones"].update(explotacion)

    # Area para modificar constantes
    def modificar_exploit_sitio(self, exploit_temporal):
        '''
            sustituye todas las cadenas APP_SITIO por el sitio proporcionado

            Parametros
            ----------
            exploit_temporal : str
                ruta del exploit temporal
        '''
        try:     
            check_output("sed -i \"s|APP_SITIO|{0}|g\" {1}".format(self.sitio, exploit_temporal),shell=True)
        except CalledProcessError:
            print("Ocurrió un error al cambiar el sitio {0} en {1}".format(self.sitio,exploit_temporal))
            
    def modificar_exploit_puerto(self, puerto, exploit_temporal):
        '''
            sustituye todas las cadenas APP_PUERTO por el puerto proporcionado
        
            Parametros
            ----------
            puerto : str
                puerto a modificar
            exploit_temporal : str
                ruta del exploit temporal
        '''
        try:
            check_output("sed -i \"s|APP_PUERTO|{0}|g\" {1}".format(puerto, exploit_temporal),shell=True)
        except CalledProcessError:
            print("Ocurrió un error al cambiar el puerto {0} en {1}".format(puerto,exploit_temporal))

    def modificar_exploit_usuario(self, usuario, exploit_temporal):
        '''
            sustituye todas las cadenas APP_USUARIO por el usuario proporcionado
        
            Parametros
            ----------
            usuario : str
                usuario a modificar
            exploit_temporal : str
                ruta del exploit temporal
        '''
        try:
            check_output("sed -i \"s|APP_USUARIO|{0}|g\" {1}".format(usuario, exploit_temporal),shell=True)
        except CalledProcessError:
            print("Ocurrió un error al cambiar el usuario {0} en {1}".format(usuario,exploit_temporal))
    
    def modificar_exploit_contrasena(self, contrasena, exploit_temporal):
        '''
            sustituye todas las cadenas APP_CONTRASENA por la contrasena proporcionada
        
            Parametros
            ----------
            contrasena : str
                contrasena a modificar
            exploit_temporal : str
                ruta del exploit temporal
        '''
        try:
            check_output("sed -i \"s|APP_CONTRASENA|{0}|g\" {1}".format(contrasena, exploit_temporal),shell=True)
        except CalledProcessError:
            print("Ocurrió un error al cambiar el contrasena {0} en {1}".format(contrasena,exploit_temporal))

    def modificar_exploit_cookie(self, cookie, exploit_temporal):
        '''
            sustituye todas las cadenas APP_COOKIE por la cookie proporcionada
        
            Parametros
            ----------
            cookie : str
                cookie a modificar
            exploit_temporal : str
                ruta del exploit temporal
        '''
        try:
            check_output("sed -i \"s|APP_COOKIE|{0}|g\" {1}".format(cookie, exploit_temporal),shell=True)
        except CalledProcessError:
            print("Ocurrió un error al cambiar el cookie {0} en {1}".format(cookie,exploit_temporal))
    
    def crear_copia_temporal(self, exploit, exploit_temporal):
        '''
            crea una copia del exploit a ejecutar
            
            Parametros
            ----------
            exploit : str
                ruta del exploit original
            exploit_temporal : str
                ruta del exploit temporal
        '''
        try:
            if not path.exists(exploit_temporal):
                check_output("cat {0} > {1}".format(exploit, exploit_temporal),shell=True)
        except CalledProcessError:
            print("No se creó la copia del exploit")
    
    def otorgar_permisos_exploit(self, exploit_temp):
        '''
            da permisos al exploit temporal
            
            Parametros
            ----------
            exploit_temp : str
                ruta del exploit temporal
        '''
        check_output("chmod +x {0}".format(exploit_temp),shell=True)

    def ejecutar_exploit(self, exploit_temp):
        '''
            ejecuta el exploit

            Parametros
            ----------
            exploit_temp : str
                combinacion de la extension y la ruta del exploit
        '''
        try:
            resultado = check_output(exploit_temp,shell=True,timeout=3)
        except (TimeoutExpired, CalledProcessError):
            return b"Inconcluso"
        return resultado

    def eliminiar_exploit_temporal(self, exploit_temp):
        '''
            elimina el exploit

            Parametros
            ----------
            exploit_temp : str
                ruta del exploit temporal
        '''
        check_output("rm {0}".format(exploit_temp),shell=True)

    def limpiar_exploit(self, exploit, lenguaje):
        '''
            obtiene la ruta del exploit temporal y prepara el exploit para ser ejecutado con su extension

            Parametros
            ----------
            exploit : str
                ruta del exploit

            lenguaje : str
                extension del exploit
        '''
        exploit_separado = exploit.rsplit(".")
        exploit_temporal = exploit_separado[0] + "_temp." + exploit_separado[1]
        exploit_preparado = lenguaje+exploit_temporal
        return exploit_temporal, exploit_preparado

    def cargar_parametros(self, producto, exploit, exploit_temporal):
        '''
            funcion que manda a llamar a las funciones para modificar sus parametros

            Parametros
            ----------
            producto : str
                producto a modificar
            exploit : str
                ruta del exploit
            exploit_temporal : str
                ruta del exploit temporal
        '''
        
        self.crear_copia_temporal(exploit, exploit_temporal)
        self.modificar_exploit_sitio(exploit_temporal)
        
        puerto = self.validar_campo("puertos")
        if type(puerto) == int:
            self.modificar_exploit_puerto(producto[puerto],exploit_temporal)
        usuario = self.validar_campo("usuarios")
        if type(usuario) == int:    
            self.modificar_exploit_usuario(producto[usuario],exploit_temporal)
        contra = self.validar_campo("contrasenas")
        if type(contra) == int:
            self.modificar_exploit_contrasena(producto[contra],exploit_temporal)
        cookie = self.validar_campo("cookie")
        if type(cookie) == int:
            self.modificar_exploit_cookie(producto[cookie],exploit_temporal)

    def validar_resultado(self, resultado):
        '''
            valida el resultado al leer el texto provocado por el exploit, si es valido o invalido

            Parametros
            ----------
            resultado : bytes
                representa el texto del exploit
        '''
        if b"Exito" in resultado:
            return 1
        elif b"Fracaso" in resultado:
            return -1
        return 0

def execute(parametros, exploits):
    '''
        lanza la ejecucion del modulo de explotacion

        Parametros
        ----------
        parametros : dict
            valores para modificar los exploits
        exploits
            conjunto de exploits sin orden
    '''
    explotacion = Explotacion(parametros, exploits)
    json_explotacion = explotacion.get_json_explotacion()
    print(json_explotacion)
    return json_explotacion