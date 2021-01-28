# Entrada

Recibe como parametros un json para iterar.

```json
parametros = {
  "subject":"Alerta",
  "fecha":"dd/mm/aaaa hh:mm",
  "sitios":[
    {
      "sitio":"http://localhost/",
      "motivo":"XSS Detectado en el input X del form Y",
      "estado":"Vulnerable"
    },
    {
      "sitio":"http://127.0.0.1/",
      "motivo":"LFI Detectado en el input X del form Y",
      "estado":"Posible Vulnerable"
    }
  ]
}
```

# Salida

Se envía un correo electrónico a las cuentas o cuenta solicitadas en el archivo strings.py

```json
resultado = "Exito"
```
