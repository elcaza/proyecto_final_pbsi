# Descripción
Módulo para obtener información sobre sitios y dominios de la organización mediante fuentes de información públicas
# Entrada
```
python3 -a https://site.com -g -t 80-100
```

```json
parametros = {
  "url":"http://site.com/",
  "Diccionarios" : 
  {
    "dork_google": "dorks_google.txt",
    "dork_bing": "dorks_bing.txt",
  },
  "google": {
    "revision" : True,
    "archivos_sql" : {
      "revision" : True
    },
    "directorios" : {
      "revision" : True
    }
  },
  "bing" : {
    "revision": True,
    "archivos_sql" : {
      "revision" : True
    },
    "directorios" : {
      "revision" : True
    }
  },
  "dnsdumper" : {
    "revision": True
  },
  "robtex" : {
    "revison":True
  }
}
```

# Salida

JSON
```json
{
  "Google":{
    "arhivos_sql": [
      "url",
      "url"
    ],
    "archivos_xlsx": [
      "url",
      "url"
    ],
    "archivos_back": [
      "url",
      "url"
    ]
  },
  "Bing":{
    "arhivos_sql": [
      "url",
      "url"
    ],
    "archivos_xlsx": [
      "url",
      "url"
    ],
    "archivos_back": [
      "url",
      "url"
    ]
  },
  "Robtex":{
    "dns":[
      {
        "domain": "ns4.unam.mx",
        "ip": "132.248.124.130",
        "country": "México",
        "header": "ApacheHTTPSApacheHTTPSTECH"
      },
      {
        "domain": "ns4.unam.mx",
        "ip": "132.248.124.130",
        "country": "México",
        "header": "ApacheHTTPSApacheHTTPSTECH"
      }
    ],
    "mx":[
      {
        "domain": "ns4.unam.mx",
        "ip": "132.248.124.130",
        "country": "México",
        "header": "ApacheHTTPSApacheHTTPSTECH"
      }
    ]
  },
  "Dnsdumpster":{
    "dns": [
      {
        "domain": "ns4.unam.mx",
        "ip": "132.248.124.130",
        "country": "México",
        "header": "ApacheHTTPSApacheHTTPSTECH"
      }
    ],
    "mx": [
      {
        "domain": "ns4.unam.mx",
        "ip": "132.248.124.130",
        "country": "México",
        "header": "ApacheHTTPSApacheHTTPSTECH"
      }
    ],
    "txt":[
      {
        "domain": "ns4.unam.mx",
        "ip": "132.248.124.130",
        "country": "México",
        "header": "ApacheHTTPSApacheHTTPSTECH"
      }
    ],
    "host":[
      {
        "domain": "ns4.unam.mx",
        "ip": "132.248.124.130",
        "country": "México",
        "header": "ApacheHTTPSApacheHTTPSTECH"
      }
    ]
  },
  "Puertos":{
    "abiertos": [
      {
        "puerto":"80",
        "protocolo":"tcp",
        "servicio":"http"
      },
      {
        "puerto":"80",
        "protocolo":"tcp",
        "servicio":"http"
      }
    ],
    "cerrados": [
      {
        "puerto":"80",
        "protocolo":"tcp",
        "servicio":"http"
      },
      {
        "puerto":"80",
        "protocolo":"tcp",
        "servicio":"http"
      }
    ],
    "filtrados": [
        {
          "puerto":"80",
          "protocolo":"tcp",
          "servicio":"http"
        },
        {
          "puerto":"80",
          "protocolo":"tcp",
          "servicio":"http"
        }
    ]
  }
}
```
