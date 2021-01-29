from modules.modelo.conector import Conector
from modules.exploits import exploits
from modules.explotacion import explotacion
from datetime import datetime
from modules.alertas import alertas
from modules.fuzzing import fuzzing
################################################## CONEXION MONGODB ##################################################
'''
    Checar estado de la conexion
'''
# con = Conector()
# con.conexion_estado()

################################################## EXPLOITS ##################################################
'''
    Guardar Exploit
'''
# json_exploit = {
#     "nombre":"exploit1.sh",
#     "contenido":"ZWNobyAiQVBQX0lQIg==",
#     "software":"Shell",
#     "biblioteca":"",
#     "gestor_contenido":""
# }
# exp = exploits.execute(json_exploit)
# con = Conector()
# con.exploit_insertar_datos(exp)

'''
    Consultar exploit
'''
# con = Conector()
# print(con.exploit_consulta_nombres())
# json_exploit_consulta_registro = {
#     "nombre":"exploit1.sh"
# }
# print(con.exploit_consulta_registro(json_exploit_consulta_registro))

'''
    Actualizar exploit
''' 
# json_exploit_actualizar = {
#     "nombre" : "pruebap.py", 
#     "ruta" : "/home/kali/Proyectos/proyecto_final_pbsi/modules/exploits", 
#     "software" : "", 
#     "biblioteca" : "", 
#     "gestor_contenido" : "Drupal" 
# }
# con.exploit_actualizar_datos(json_exploit_actualizar)

'''
    Eliminar Base de exploits
'''
# con = Conector()
# con.exploit_eliminar_base_total()


################################################## EXPLOITS ##################################################

################################################## EXPLOTACION | IDENTIFICACION ##################################################
'''
    Buscar exploits y ejecutar exploits
'''
con = Conector()
json_explotacion = {"ip":"192.168.0.1", "puerto": 1001}
res = con.exploit_buscar_software("JS")
for r in res["exploits"]:
    ruta = r["ruta"]
    lenguaje = r["lenguaje"]
    explotacion.execute(json_explotacion,ruta,lenguaje)

################################################## EXPLOTACION | IDENTIFICACION ##################################################

################################################## ALERTAS ##################################################
'''
    Enviar alertas
'''
# con = Conector()
# json_alerta = {
#     "subject":"Alerta generada automáticamente",
#     "sitios":[
#             {
#                 "sitio":"http://sitio1.com",
#                 "motivo":"CMS vulnerable a Drupalgeddon2",
#                 "estado":"Comprometido"
#             },
#             {
#                 "sitio":"192.168.0.1",
#                 "motivo":"LFI en el input \"search\"",
#                 "estado":"Posible vulnerable"
#             },
#             {
#                 "sitio":"http://sitio2.com",
#                 "motivo":"XSS en el input \"username\"",
#                 "estado":"Comprometido"
#             }
#         ],
#     "fecha":datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
# }
# alertas.execute(json_alerta)

################################################## ALERTAS ##################################################

################################################## FUZZING ##################################################

# json_fuzzing = {
#     "url":"https://xss-game.appspot.com/level1",
#     "hilos":1,
#     "diccionario_ataque_xss":"./fuzzing/xss.txt",
#     "diccionario_ataque_sqli":"./fuzzing/sqli.txt",
#     "diccionario_ataque_lfi":"./fuzzing/lfi.txt",
#     "diccionario_validacion_sqli":"./fuzzing/sqli_manejadores.txt",
#     "diccionario_validacion_lfi":"./fuzzing/lfi_sistemas.txt",
#     "cookie":"PHDSESSID:jnj8mr8fugu61ma86p9o96frv0",
#     "manejador":"",
#     "sistema_operativo":"Linux"
# }

# fuzzing.execute(json_fuzzing)