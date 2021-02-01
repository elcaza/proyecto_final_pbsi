from modules.modelo.conector import Conector
from modules.exploits import exploits
from modules.explotacion import explotacion
from datetime import datetime
from modules.alertas import alertas
from modules.fuzzing import fuzzing
from modules.ejecucion import ejecucion
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
#     "software":{
#         "nombre":"Drupal",
#         "version":"7.57"
#     }
# }

# exp = exploits.execute(json_exploit)
# con = Conector()
# con.exploit_insertar_datos(exp)

# json_exploit = {
#     "nombre":"exploit6.py",
#     "contenido":"ZnJvbSB0aW1lIGltcG9ydCBzbGVlcAoKc2xlZXAoNjApCgpwcmludCgiRXhpdG8iKQ==",
#     "cms":{
#         "nombre_cms":"Drupal",
#         "categoria":"Plugin",
#         "nombre_cms_extension":"Form 9",
#         "version":"1.5"
#     }
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
#     "exploit":"exploit2.sh"
# }
# print(con.exploit_consulta_registro(json_exploit_consulta_registro))

'''
    Actualizar exploit
''' 
# con = Conector()
# json_exploit_actualizar = {
#     "nombre":"exploit2.sh",
#     "contenido":"ZWNobyBFWElUTwo=",
#     "software":{
#         "nombre":"Drupal",
#         "version":"7.58"
#     }
# }

# exp = exploits.execute(json_exploit_actualizar)
# con = Conector()
# con.exploit_actualizar_datos(exp)

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
# con = Conector()

# res = con.exploit_buscar_software_general("drup")
# print(res)
# print("--------------------------------------------")
# res = con.exploit_buscar_software_especifico("drup","7.57")
# print(res)
# print("--------------------------------------------")

# con = Conector()
# json_explotacion = {
#     "dominio":"192.168.0.1", #"dominios.com"
#     "puerto": 1001, 
#     "pagina": "http://fitio1.com/vuln.kol"
# }

# json_identificar = {
#     "cms_nombre":"Drupal",
#     "cms_categoria":"7.57"
# }

# res = con.exploit_buscar_cms(json_identificar,3)
# explotacion.execute(json_explotacion,res["exploits"])

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
################################################## FUZZING ##################################################

################################################## EJECUCION ##################################################

'''
    Ejecución
    Módulo para programar escaneos a determinados sitios o rangos de IP mediante una interfaz web pudiendo configurar determinados 
    puertos de revisión y 
    programarlos en intervalos específicos. 
    Esto debe correr como demonio haciendo la identificación y análisis de sitios.
'''


################################################## EJECUCION ##################################################