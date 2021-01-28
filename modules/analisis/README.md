# Módulo - Análisis

# Dependencias
+ dirb
+ curl
+ nmap


# Entrada
urls en el formato

http://site.com

# Salida
Va a ser un json

```json
bd = {
    "datos_servidor":{
        "server":"apache",
        "version":"2.7"
    },
    "directorios_interes":[
        "url",
        "url",
        "url"
    ],
    "bibliotecas_usadas":[
        "url",
        "url"
    ],
    "cabeceras":{
        "presentes":[
            "cabecera",
            "cabecera"
        ],
        "ausentes":[
            "cabecera",
            "cabecera"
        ]
    },
    "cifrados":{
        "debiles":[
            "a",
            "b"
        ]
    },
    "protocolos":{
        "inseguros":[
            "a",
            "b"
        ]
    },
    "ioc":{
        "mineros":[],
        "webshells":[],
        "contenido_anomalo":[]
    }
}
```