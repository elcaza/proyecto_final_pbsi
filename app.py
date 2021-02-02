# Importaciones
## Flask
import re
from flask import Flask, render_template, request
from flask_cors import CORS

## Utileria
from base64 import decode, encode
from os import path
from datetime import datetime

## Modulos
from modules.obtencion_informacion import obtener_informacion
from modules.alertas import alertas
#from modules.analisis import analisis
#from modules.consulta import consulta
from modules.exploits import exploits
from modules.explotacion import explotacion
from modules.fuzzing import fuzzing
from modules.modelo.conector import Conector
#from modules.ejecucion import ejecucion

root = path.abspath(path.dirname(__file__))
app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = 'datosrandomjamasvistos'

'''
    Modo de ejecucion:
        
        Ejecucion -> Obtener_informacion -> Análisis [Ejecucion de Fuzzing[Hilos] -> Lista de vulnerabilidades y Lista de posibles vulnerabilidades]
            -> Identificacion -> Explotacion [-> Lista de vulnerabilidades, Lista de posibles vulnerabilidades y Lista de Fracasos]
                -> Reporte

        Base de exploits
        Consulta
'''

def iniciar_analisis(peticion_json):
    ''' 
        Obtener informacion
        Estado : En desarrollo
        Errores:
            DNSDumpster:
                List index out of range
            Robtex:
                429 error retrieving https://freeapi.robtex.com/ipquery/132.248.124.130: {"status":"ratelimited"}:
                    TypeError: 'NoneType' object is not subscriptable
            Google:
                No da resultados
            Bing:
                No da resultados
            IPV4Info:
                No da resultados
        Errores menores:
            DNSDumpster:
                Se repiten los resultados en varias ocasiones
            Robtex:
                Se repiten los resultados en varias ocasiones                
    '''
    # respuesta_obtener_informacion = obtener_informacion.execute(peticion_json)
    # print(respuesta_obtener_informacion)
    '''
        Analisis
        Estado : Por desarrollar
    '''
    # respuesta_analisis = analisis.execute(peticion_json)
    # print(respuesta_analisis)
    '''
        Fuzzing
        Estado : En desarrollo
        Errores : 

        Errores menores:
    '''
    json_fuzzing = {
        "url":"http://www.altoromutual.com:8080/login.jsp",
        "hilos":4,
        "cookie":"PHDSESSID:jnj8mr8fugu61ma86p9o96frv0"
    }
    respuesta_fuzzing = fuzzing.execute(json_fuzzing)
    print(respuesta_fuzzing)

@app.route("/")
def index():
    return render_template("app.html")

# @app.route("/ejecucion",methods=["GET","POST"])
# def ejecucion():
#     if request.method == "POST":
#         peticion_json = request.get_json()
#         validar_json_ejecucion(peticion_json)
#         iniciar_analisis(peticion_json)
#         print(respuesta)
#         return respuesta

# @app.route("/consulta", methods=["GET","POST"])
# def consulta():
#     if request.method == "POST":
#         peticion_json = request.get_json()
#         validar_json_consulta(peticion_json)
#         respuesta = consulta.execute(peticion_json)
#         print(respuesta)
#         return respuesta

# @app.route("/exploits", methods=["GET","POST"])
# def exploits():
#     if request.method == "POST":
#         peticion_json = request.get_json()
#         validar_json_exploit(peticion_json)    
#         respuesta = exploits.execute(peticion_json)
#         print(respuesta)
#         return respuesta

# @app.route("/programar",methods=["GET","POST"])
# def programar():
#     if request.method == "POST":
#         peticion_json = request.get_json()
#         validar_json_programar(peticion_json)
#         respuesta = programar.execute(peticion_json)
#         print(respuesta)
#         return respuesta

# Ejecucion de Flask
'''
    Nota:
        Es necesario usar WSGI para implementar el WebService, por qué?
            Si truena en algún lado continua con la ejecución y levanta otra "instancia"
            Permite más de una conexión
            Permite personalizar las opciones de seguridad
            Pueden ser:
                Apache (Algo complicado, pero más personalizable)
                Gunicorn (Muy fácil)
                Bjoern (Es muy rápido, no lo he probado) 
'''

peticion = {
	"sitio":"http://seguridad.unam.mx",
	"dnsdumpster" : {
		"revision":True,
		"dns" : True,
		"txt" : True,
		"host" : True,
		"mx" : False

	},
	"robtex" : {
		"revision":True,
		"informacion":True,
		"dns_forward":False,
		"mx_forward":True,
		"host_forward":False,
		"host_reverse":True
	},
	"puertos" : { 
		"revision" : True,
		"opcion" : "rango",
		"rango" : {
			"inicio" : 20,
			"final" : 100
		}
	}
}

if __name__ == "__main__":
    iniciar_analisis(peticion)
    app.run(host='127.0.0.1', port=3000, debug=True)
    print("golas")