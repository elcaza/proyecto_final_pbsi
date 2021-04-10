from subprocess import check_output, CalledProcessError, TimeoutExpired
from os import path
import threading
from time import sleep

class Lanzar_exploit(threading.Thread):
    '''
        Clase para copiar los exploits y poderlos modificar de acuerdos las datos recabados del modulo de 
        obtener informacion y analisis

        .........
        Atributos
        ---------
        nombre : str
            nombre del exploit
        
        threadID : int
            id del hilo
        
        parametros : dict
            valores que contienen el sitio y puertos

        exploit : dict
            valores que contienen la ruta del exploit junto con su extension 

        resultado : dict
            guarda el resultado de cada ejecucion del exploit

        json_explotacion : dict
            guarda el conjunto de resultados

        Metodos
        -------
        run():
            se ejecuta por defecto al iniciar el hilo el cual lanza las funciones para extraer el exploit y sus valores para iterar

        get_resultado():
            regresa el resultado del exploit

        get_nombre():
            regresa el nombre del exploit

        get_json_explotacion():
            regresa el json_explotacion

        set_puertos():
            obtiene de los parametros los puertos a iterar

        set_sitio():
            obtiene el sitio de los parametros

    '''
    def __init__(self, threadID, nombre, parametros, exploit):
        threading.Thread.__init__(self)
        self.nombre = nombre
        self.threadID = threadID
        self.parametros = parametros
        self.exploit = exploit
        self.set_puertos()
        self.set_sitio()
        self.resultado = {}
        
    def run(self):
        '''
            se ejecuta por defecto al iniciar el hilo el cual lanza las funciones para extraer el exploit y sus valores para iterar
        '''
        print ("Starting " + self.nombre)
        exploit_temporal, exploit_preparado = limpiar_exploit(self.exploit["exploit"], self.exploit["lenguaje"])
        for puerto in range(len(self.puertos)):
            cargar_parametros(self.sitio, self.puertos[puerto], self.exploit["exploit"], exploit_temporal)
            otorgar_permisos_exploit(exploit_temporal)
            print(exploit_preparado)
            self.resultado[self.puertos[puerto]] = ejecutar_exploit(exploit_preparado)
            self.resultado[self.puertos[puerto]] = validar_resulado(self.resultado[self.puertos[puerto]])
            eliminiar_exploit_temporal(exploit_temporal)
        print ("Exiting " + self.nombre)

    def get_resultado(self):
        '''
            regresa el resultado del exploit
        '''
        return self.resultado
    
    def get_nombre(self):
        '''
            regresa el nombre del exploit
        '''
        nombre = self.exploit["exploit"].rsplit("/")[-1]
        nombre = nombre.replace(".","_")
        return nombre

    def get_json_explotacion(self):
        '''
            regresa el json_explotacion
        '''
        return {self.get_nombre():self.get_resultado()}
    
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

# Area para modificar constantes
def modificar_exploit_sitio(dominio, exploit, exploit_temporal):
    '''
        sustituye todas las cadenas APP_SITIO por el sitio proporcionado

        Parametros
        ----------
        dominio : str
            dominio o sitio a explotar
        exploit : str
            ruta del exploit original
        exploit_temporal : str
            ruta del exploit temporal
    '''
    try:
        if not path.exists(exploit_temporal):
            check_output("sed \"s|APP_SITIO|{0}|g\" {1} > {2}".format(dominio, exploit, exploit_temporal),shell=True)
        else:
            check_output("sed -i \"s|APP_SITIO|{0}|g\" {1}".format(dominio, exploit_temporal),shell=True)
    except CalledProcessError:
        print("Ocurrió un error al cambiar el sitio {0} en {1}".format(dominio,exploit))
        
def modificar_exploit_puerto(puerto, exploit, exploit_temporal):
    '''
        sustituye todas las cadenas APP_PUERTO por el puerto proporcionado
    
        Parametros
        ----------
        puerto : str
            puerto a modificar
        exploit : str
            ruta del exploit original
        exploit_temporal : str
            ruta del exploit temporal
    '''
    try:
        if not path.exists(exploit_temporal):
            check_output("sed \"s|APP_PUERTO|{0}|g\" {1} > {2}".format(puerto, exploit, exploit_temporal),shell=True)
        else:
            check_output("sed -i \"s|APP_PUERTO|{0}|g\" {1}".format(puerto, exploit_temporal),shell=True)
    except CalledProcessError:
        print("Ocurrió un error al cambiar el puerto {0} en {1}".format(puerto,exploit))

def crear_copia_temporal(exploit, exploit_temporal):
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
# Fin del area
def otorgar_permisos_exploit(exploit_temp):
    '''
        da permisos al exploit temporal
        
        Parametros
        ----------
        exploit_temp : str
            ruta del exploit temporal
    '''
    check_output("chmod +x {0}".format(exploit_temp),shell=True)

def ejecutar_exploit(exploit):
    '''
        ejecuta el exploit

        Parametros
        ----------
        exploit : str
            combinacion de la extension y la ruta del exploit
    '''
    try:
        resultado = check_output(exploit,shell=True,timeout=3)
    except (TimeoutExpired, CalledProcessError):
        return b"Inconcluso"
    return resultado

def eliminiar_exploit_temporal(exploit_temp):
    '''
        elimina el exploit

        Parametros
        ----------
        exploit_temp : str
            ruta del exploit temporal
    '''
    check_output("rm {0}".format(exploit_temp),shell=True)

def limpiar_exploit(exploit, lenguaje):
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

def cargar_parametros(sitio, puerto, exploit, exploit_temporal):
    '''
        funcion que manda a llamar a las funciones para modificar sus parametros

        Parametros
        ----------
        sitio : str
            sitio a explotar
        puerto : str
            puerto a modificar
        exploit : str
            ruta del exploit
        exploit_temporal : str
            ruta del exploit temporal
    '''
    crear_copia_temporal(exploit, exploit_temporal)
    modificar_exploit_sitio(sitio,exploit, exploit_temporal)
    modificar_exploit_puerto(puerto,exploit, exploit_temporal)

def validar_resulado(resultado):
    '''
        valida el resultado al leer el texto provocado por el exploit, si es valido o invalido

        Parametros
        ----------
        resultado : bytes
            representa el texto del exploit
    '''
    print(resultado)
    if b"Exito" in resultado:
        return 1
    elif b"Fracaso" in resultado:
        return -1
    return 0

def obtener_exploits(exploits):
    '''
        añade a la lista de exploit la ruta y su extension

        Parametros
        ----------
        exploits : array
            arreglo de diccionarios que tienen los datos del exploit
    '''
    lista_exploits = []
    for exploit in exploits:
        lista_exploits.append({"exploit":exploit["ruta"],"lenguaje":exploit["lenguaje"]})
    return lista_exploits

def definir_cantidad_hilos(lista_exploits):
    '''
        hace el calculo para definir la cantidad de hilos necesarios para lanzar los exploit

        Parametros
        ----------
        lista_exploits : array
            lista que contiene a los exploit
    '''
    divisor = int(len(lista_exploits) / 4)
    modulo = len(lista_exploits) % 4
    if divisor > 0:
        return 4
    return modulo

def crear_hilos_exploit(parametros, lista_exploits):
    '''
        permite lanzar a los hijos que a su vez ejecutan el exploit para guardar el resultado en json_explotacion

        itera los exploits y por la cantidad de hijos, a cada hijo le asigna una cantidad determinada de exploits y lanza al hijo

        Parametros
        ----------
        parametros : dict
            contiene los valores de los exploits

        lista_exploits : array
            lista que contiene valores exactos de los exploits
    '''    
    json_explotacion = {"explotaciones":{}}
    hijos = []
    hilos = definir_cantidad_hilos(lista_exploits)

    for exploit in range(0, len(lista_exploits), hilos):
        for hilo in range(hilos):
            try:
                hijos.append(Lanzar_exploit(hilo,"Thread-{0}".format(hilo),parametros,lista_exploits[exploit+hilo]))
            except IndexError:
                break

        for hilo in range(hilos):
            try:
                hijos[hilo].start()
            except IndexError:
                break
            
        for hilo in range(hilos):
            try:
                hijos[hilo].join(600)
            except IndexError:
                break

        for hilo in range(hilos):
            try: 
                explotacion = hijos[hilo].get_json_explotacion()
                json_explotacion["explotaciones"].update(explotacion)
            except IndexError:
                break
        hijos = []

    return json_explotacion

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
    lista_exploits = obtener_exploits(exploits)
    json_explotacion = crear_hilos_exploit(parametros, lista_exploits)
    return json_explotacion