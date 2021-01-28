# Entrada


```json
{
    "url":"http://pagina.com/",
    "hilos":1,
    "cookies":"PHPSESSID:AS43BCYS,OTRA:FGVX34R"(separado por comas),
    "manejador_bd":"MySQL",
    "sistema_operativo":"Linux",
    "Diccionarios": 
    {
        "xss_ataque":"base64"|"xss.txt",
        "sqli_ataque":"base64"|"sql.txt",
        "sqli_verificacion":"base64"|"sql_validacion.txt",
        "lfi_ataque":"base64"|"lfi.txt",
        "lfi_verificacion":"base64"|"lfi_verificacion.txt",
    }
}
```


# Salida

```json
{
    "url":"http://pagina.com/",
    "ataque":"XSS",
    "tipo":"No exitoso",
    "form":[
    {
        "form1":[
             {
                "nombre":"username",
                "id":"id_username",
                "valor":"<script>Alert();</script>"
             },
             {
                "nombre":"password",
                "id":"",
                "valor":"<script>Alert();</script>"
             }
         ]
     },
        "form2":[
             {
                "nombre":"username",
                "id":"id_username",
                "valor":"<script>Alert();</script>"
             },
             {
                "nombre":"password",
                "id":"",
                "valor":"<script>Alert();</script>"
             }
         ]
      }
   ]
}
```
