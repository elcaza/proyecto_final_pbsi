peticion = {
    "sitio":"http://seguridad.unam.mx",
    # "sitio":"seguridad.unam.mx"
    # Obtener informacion
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
    },
    # Analisis
    "algo":"",
    #Fuzzing
    "cookie":"PHDSESSID:jnj8mr8fugu61ma86p9o96frv0",
    "hilos":4,
    #Explotacion
    "profundidad":2
}

peticion_transformada = {
    "sitio":"altoromutual.com:8080",
    "informacion":{
        "DNS":[
            {
                "ip":"127.0.0.1",
                "registros":["ns","mx","a","aaaa"]
            }
        ],
        "Puertos":[
            {
                "puerto":"22",
                "servicio":"ssh"
            }
        ]
    },
    "analisis":{
        "CMS":{
            "nombre":"drupal",
            "version":"7.57"
        },
        "Servidor":{
            "nombre":"Apache",
            "version":"1.14"
        },
        "Cifrados":[
            {
                "nombre":"SSL",
                "version":"2"
            },
            {
                "nombre":"ECDH",
                "version":"256"
            }
        ]
    },
    "paginas":[
        {
            "sitio":"https://xss-game.appspot.com/level1",
            #"forms":[{}]
        }
    ],
    "cookie":"PHDSESSID:jnj8mr8fugu61ma86p9o96frv0",
    "estado":{
        "fecha":""
    }
    #"Explotacion":[{}]
}