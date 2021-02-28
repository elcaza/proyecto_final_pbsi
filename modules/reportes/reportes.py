from datetime import datetime
from modules import strings

class Reporte():
    def __init__(self, parametros):
        self.set_sitio(parametros)
        self.set_fecha(parametros)
        self.set_analisis(parametros)

    def set_sitio(self, parametros):
        if "sitio" in parametros:
            self.sitio = parametros["sitio"]
        else:
            self.sitio = ""

    def set_fecha(self, parametros):
        if "fecha" in parametros:
            self.fecha = parametros["fecha"]
        else:
            self.fecha = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    def set_analisis(self, parametros):
        if "analisis" in parametros:
                self.analisis = parametros["analisis"]
        else:
            self.analisis = []

    def get_sitio(self):
        return self.sitio

    def get_fecha(self):
        return self.fecha

    def crear_mensaje_sitio(self):
        self.correo_mensaje_texto = self.get_html()+self.get_head()+self.get_body_inicio()
        for sitio in self.sitios:
            sitio_vulnerable = self.get_body_sitio(sitio["sitio"])
            motivo = self.get_body_motivo(sitio["motivo"])
            estado = self.get_body_estado(sitio["estado"])
            salto = self.get_body_salto()
            self.correo_mensaje_texto += sitio_vulnerable+motivo+estado+salto
        self.correo_mensaje_texto += self.get_body_fin()

    def get_html(self):
        html = """
        <html xmlns="http://www.w3.org/1999/xhtml" xmlns:o="urn:schemas-microsoft-com:office:office"
            style="width: 100% ;font-family: sans-serif; padding: 0; margin: 0;">
        """
        return html

    def get_head(self):
        head = """
            <head>
                <meta http-equiv="Content-Security-Policy"
                    content="script-src 'none'; connect-src 'none'; object-src 'none'; form-action 'none';">
                <meta charset="UTF-8">
                <meta content="width=device-width, initial-scale=1" name="viewport">
                <meta name="x-apple-disable-message-reformatting">
                <meta http-equiv="X-UA-Compatible" content="IE=edge">
                <meta content="telephone=no" name="format-detection">
            {0}
            </head>
        """.format(self.get_css())
        return head

    def get_css(self):
        css = '''
            <style type="text/css">

            body {
                margin: 0;
                padding: 0;
            }
            
            div{
                text-align: center;
            }

            table{
                margin: 0 auto;
            }

            .contenedor-grafica {
                width: 600px;
                margin-left: auto;
                margin-right: auto;
            }

            .contenedor-titulo {
                background-color: #044767;
                width: auto;
                margin: auto;
            }

            .titulo {
                line-height: 80px;
                font-size: 36px;
                font-family: sans-serif;
                color: #FFFFFF;
                margin: 0;
                padding: 0;
            }

            .subtitulo {
                text-align: center;
            }

            .grafica {
                width: inherit;
            }

            .categoria {
                margin-left: 20;
            }

            .fracaso {
                background-color: #ff000091;
            }

            .exito {
                background-color: #027fff99;
            }

            .inconcluso {
                background-color: yellow;
            }

            .tabla-descripcion-grafica {
                table-layout: fixed;
                width: 90%;
                border-collapse: collapse;
                margin: auto;
            }

            .tabla-descripcion-renglon-grafica {
                padding: 20px;
            }

            .tabla-descripcion-renglon {
                padding: 10px;
            }

            .contenedor-grafica{
                margin-top:40px;
            }

            .linea-divisora {
                margin-left: 20px;
                margin-right: 20px;
                margin-bottom: 30px;
                margin-top: 25px;
            }

            .linea-doble-divisora {
                margin-left: 20px;
                margin-right: 20px;
                margin-bottom: 30px;
                margin-top: 25px;
                border-top: double;
            }

            thead th:nth-child(1) {
                width: 10%;
            }

            thead th:nth-child(2) {
                width: 40%;
            }

            thead th:nth-child(3) {
                width: 10%;
            }

            th,
            td {
                letter-spacing: 1px;
            }

            tbody td {
                text-align: center;
            }

            tbody tr:nth-child(odd) {
                background-color: #027fb99b;
            }

            tbody tr:nth-child(even) {
                background-color: #ececec;
            }

        </style>
        '''
        return css

    def get_body_titulo(self):
        body_titulo = '''
            <body>
                <!-- Header -->
                <div class="contenedor-titulo">
                    <h1 class="titulo">
                        UNAM CERT
                    </h1>
                </div>
        '''
        return body_titulo

    def get_body_subtitulo_reporte(self):
        body_subtitulo_reporte = '''
            <h2 class="subtitulo">
                REPORTE DEL SITIO {0}
            </h2>
            <!-- Fecha del analisis-->
            <h4 class="subtitulo">
                {1}
            </h4>
            <hr class="linea-doble-divisora">
        '''.format(self.sitio, self.fecha)
        return body_subtitulo_reporte

    def get_body_categoria(self, categoria):
        body_categoria = '''
            <h3 class="categoria">
                {0}
            </h3>
            <hr class="linea-divisora">
        '''.format(categoria)
        return body_categoria

    def get_body_titulo_grafica(self, titulo):
        body_titulo = '''
            <h3 class="subtitulo">
                {0}
            </h3>
        '''.format(titulo)
        return body_titulo

    def get_body_grafica(self, grafica):
        body_categoria = '''
            <div class="contenedor-grafica">                           
                </iframe>                           
                    <iframe src="{0}" width="100%" height="400">
                </iframe>
            </div>
        '''.format(grafica)
        return body_categoria

    def get_body_descripcion(self, grafica, cabeceras, datos):
        if grafica == 1:
            tabla_grafica = '''
            <div>
                <table class="tabla-descripcion-grafica" cellspacing="0">
                    <thead>
                        <tr>
            '''
            for cabecera in cabeceras:
                tabla_grafica += '''<th class="tabla-descripcion-renglon-grafica" scope="col">{0}</th> '''.format(cabecera)
            tabla_grafica += ''' 
                        </tr>
                    </thead>
                    <tbody>
                    '''
            for dato in datos:
                tabla_grafica += "<tr>"
                for posicion_dato in range(len(dato)):
                    if posicion_dato == 0:
                        tabla_grafica += '''<th class="tabla-descripcion-renglon-grafica" scope="row">{0}</th>'''.format(dato[posicion_dato])
                    elif str(dato[posicion_dato]) in "Exitoso":
                        tabla_grafica += '''<td class="exito tabla-descripcion-renglon-grafica">{0}</td>'''.format(dato[posicion_dato])
                    elif str(dato[posicion_dato]) in "Fracaso":
                        tabla_grafica += '''<td class="fracaso tabla-descripcion-renglon-grafica">{0}</td>'''.format(dato[posicion_dato])
                    elif str(dato[posicion_dato]) in "Inconcluso":
                        tabla_grafica += '''<td class="inconcluso tabla-descripcion-renglon-grafica">{0}</td>'''.format(dato[posicion_dato])
                    else:
                        tabla_grafica += '''<td class="tabla-descripcion-renglon-grafica">{0}</td>'''.format(dato[posicion_dato])
                tabla_grafica += "</tr>"
            tabla_grafica += ''' 
                        </tbody>
                    </table>
                </div>
                '''
            return tabla_grafica
        else:
            tabla = '''
            <div>
                <table cellspacing="0">
                    <thead>
                        <tr>
            '''
            for cabecera in cabeceras:
                tabla += '''<th class="tabla-descripcion-renglon" scope="col">{0}</th> '''.format(cabecera)
            tabla += ''' 
                        </tr>
                    </thead>
                    <tbody>
                    '''
            for dato in datos:
                tabla += "<tr>"
                for posicion_dato in range(len(dato)):
                    if posicion_dato == 0:
                        tabla += '''<th class="tabla-descripcion-renglon" scope="row">{0}</th>'''.format(dato[posicion_dato])
                    else:
                        tabla += '''<td class="tabla-descripcion-renglon">{0}</td>'''.format(dato[posicion_dato])
                tabla += "</tr>"
            tabla += ''' 
                        </tbody>
                    </table>
                </div>
                '''
            return tabla

    def get_body_analisis(self):
        body_analisis = ""
        for categoria in self.analisis:
            grafica = 0
            if categoria["categoria"] != "":
                body_analisis += self.get_body_categoria(categoria["categoria"])
            body_analisis += self.get_body_titulo_grafica(categoria["titulo"])
            if categoria["grafica"] != "":
                body_analisis += self.get_body_grafica(categoria["grafica"])
                grafica = 1
            body_analisis += self.get_body_descripcion(grafica, categoria["cabecera"],categoria["datos"])
            #body_analisis += '''<hr class="linea-doble-divisora">'''
        return body_analisis

    def get_body(self):
        body = self.get_body_titulo()+self.get_body_subtitulo_reporte()+self.get_body_analisis()
        return body

    def get_footer(self):
        footer = '''<hr class="linea-doble-divisora">
            <div class="contenedor-titulo"">
                <img src=" https://congreso.seguridad.unam.mx/2016/sites/default/themes/theme2016/images/unam_negro.png"
                width="56px" height="56px" style="vertical-align: middle; border: 0; max-width: 100%; padding-right: 4px;">
                <h4 style="line-height: 80px; font-family: sans-serif; color:#FFFFFF; margin: 0; padding: 0; display: inline;">
                    Coordinación de Seguridad de la Información
                </h4>
                <img src="https://congreso.seguridad.unam.mx/2016/sites/default/themes/theme2016/images/cert_negro.png"
                    width="56px" height="56px" style="vertical-align:middle; border: 0; max-width: 100%;">
            </div>
        </body>

        </html>'''
        return footer

    def crear_reporte(self):
        reporte_html = self.get_html()+self.get_head()+self.get_body()+self.get_footer()
        with open("reporte.html","w") as reporte:
            reporte.write(reporte_html)
            
def execute(paremetros):
    reporte = Reporte(paremetros)
    reporte.crear_reporte()
    print("Reporte creado")