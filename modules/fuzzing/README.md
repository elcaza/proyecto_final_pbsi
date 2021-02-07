# Entrada


```json
{
   "url":"http://pagina.com/",
   "hilos":1,
   "cookies":"PHPSESSID:AS43BCYS,OTRA:FGVX34R"(separado por comas),
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
