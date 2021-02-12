# Entrada


```json
{
   "url":"http://pagina.com/",
   "cookies":"PHPSESSID:AS43BCYS,OTRA:FGVX34R"(separado por comas),
}
```


# Salida

```json
{
  "forms": {
    "form1": [
      {
        "nombre": "username",
        "id": "id_username",
        "valor": "<script>Alert();</script>"
      },
      {
        "nombre": "password",
        "id": "",
        "valor": "<script>Alert();</script>"
      }
    ],
    "form2": [
      {
        "nombre": "username",
        "id": "id_username",
        "valor": "<script>Alert();</script>"
      },
      {
        "nombre": "password",
        "id": "",
        "valor": "<script>Alert();</script>"
      }
    ]
  }
}
```
