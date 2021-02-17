import requests
import json

def ejecutar(peticion, headers):
    r = requests.post("http://127.0.0.1:3000/ejecucion",data=json.dumps(peticion), headers=headers)
    print(r.text)

headers = {
    "Content-Type": "application/json; charset=utf-8"
}

peticion = {
	"sitio":"http://altoromutual.com:8080",
    "ejecucion":"",
	"dnsdumpster" : {
		"revision":True,
		"dns" : True,
		"txt" : True,
		"host" : True,
		"mx" : True

	},
	"robtex" : {
		"revision":True,
		"informacion":True,
		"dns_forward":True,
		"mx_forward":True,
		"host_forward":True,
		"host_reverse":True
	},
	"puertos" : { 
		"revision" : True,
		"opcion" : "rango",
		"rango" : {
			"inicio" : 8070,
			"final" : 8090
		}
	},
    # Analisis
    "algo":"",
    #Fuzzing
    "cookie":"PHDSESSID:jnj8mr8fugu61ma86p9o96frv0",
    "hilos":4,
    #Explotacion
    "profundidad":2
}

ejecutar(peticion, headers)