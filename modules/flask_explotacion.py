from modelo import strings 
from modelo.conector import Conector
from exploits import exploits
from explotacion import explotacion

'''
    Guardar exploit
'''
# exp = exploits.execute("exploit2.sh","ZWNobyAiQVBQX0lQIg==","Shell","","")
# con = Conector()
# con.exploit_insertar_datos(exp)

'''
    Consultar exploit
'''
# con = Conector()
# print(con.exploit_consulta_nombres())
# print(con.exploit_consulta_registro("pruebap.py"))

'''
    Checar estado y actualizar
'''
# con = Conector()
# con.conexion_estado()
# con.exploit_actualizar_datos({"nombre" : "pruebap.py", "ruta" : "/home/kali/Proyectos/proyecto_final_pbsi/modules/exploits", "software" : "asl", "biblioteca" : "ab", "gestor_contenido" : "ac" })

'''
    Buscar exploits y ejecutar exploits
'''
# con = Conector()
# json_explotacion = {"ip":"192.168.0.1", "puerto": 1001}
# res = con.exploit_buscar_software("Shell")
# for r in res["exploits"]:
#     ruta = r["ruta"]
#     lenguaje = r["lenguaje"]
#     explotacion.execute(json_explotacion,ruta,lenguaje)

'''
    Eliminar Base de exploits
'''
# con = Conector()
# con.exploit_eliminar_base_total()

'''
    Buscar registro
'''
#con.exploit_consulta_registro("exploit1.py")

'''
    Actualizar exploit
'''
#con.exploit_actualizar_datos({"nombre" : "pruebap.py", "ruta" : "/home/kali/Proyectos/proyecto_final_pbsi/modules/exploits", "software" : "asl", "biblioteca" : "ab", "gestor_contenido" : "ac" })
