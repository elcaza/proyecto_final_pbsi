from datetime import datetime

class Reporte():
    '''
        Clase que permite crear los reportes html

        .........
        Atributos
        ---------
            sitio : str
                nombre del sitio

            fecha : str
                fecha del analisis

            analisis : array
                contiene a todos los analisis de cada seccion del reporte para ser iterado

            parametros : dict
                contiene el conjunto de valores para la creacion del reporte

        Metodos
        -------
            set_sitio():
                obtiene el sitio de los parametros

            set_fecha():
                obtiene la fecha de los parametros

            set_analisis():
                obtiene los analisis de los parametros

            get_sitio():
                regresa el nombre sitio

            get_fecha():
                regresa la fecha

            get_html():
                regresa la etiqueta html

            get_head():
                regresa el header 

            get_css():
                regresa la referencia al archivo css

            get_body_titulo():
                regresa la barra de navegacion y banner

            get_body_subtitulo_reporte():
                regresa el subtitulo del reporte en este caso sitio con su fecha

            get_body_categoria(categoria):
                agrega la etiqueta categoria

            get_body_titulo_grafica(titulo):
                agrega la etiqueta de titulo a la grafica

            get_body_grafica(grafica):
                agrega el espacio para mostrar le iframe de la grafica

            get_body_descripcion(grafica, cabeceras, datos):
                agrega una tabla que muestra los datos analizados por anteriores modulos

            get_body_analisis():
                funcion que sirve para iterar los analisis e ir agregando etiquetas

            get_body():
                funcion integredora de etiquetas que forman el body

            get_footer():
                regresa el footer

            crear_reporte():
                crea el documento html con todas las secciones creadas previamente

    '''
    def __init__(self, parametros):
        self.parametros = parametros
        self.set_sitio()
        self.set_fecha()
        self.set_analisis()

    def set_sitio(self):
        '''
            obtiene el sitio de los parametros
        '''
        if "sitio" in self.parametros:
            self.sitio = self.parametros["sitio"]
        else:
            self.sitio = ""

    def set_fecha(self):
        '''
            obtiene la fecha de los parametros
        '''
        if "fecha" in self.parametros:
            self.fecha = self.parametros["fecha"]
        else:
            self.fecha = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    def set_analisis(self):
        '''
            obtiene los analisis de los parametros
        '''
        if "analisis" in self.parametros:
                self.analisis = self.parametros["analisis"]
        else:
            self.analisis = []

    def get_sitio(self):
        '''
            regresa el nombre sitio
        '''
        return self.sitio

    def get_fecha(self):
        '''
            regresa la fecha
        '''
        return self.fecha

    def get_html(self):
        '''
            regresa la etiqueta html
        '''
        html = """
        <html xmlns="http://www.w3.org/1999/xhtml" xmlns:o="urn:schemas-microsoft-com:office:office"
            style="width: 100% ;font-family: sans-serif; padding: 0; margin: 0;">
        """
        return html

    def get_head(self):
        '''
            regresa el header 
        '''
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
        '''
            regresa la referencia al archivo css
        '''
        css = '''
            <link rel="stylesheet" href="{{ url_for('static', filename='css/new_reporte.css') }}">
        '''
        return css

    def get_body_titulo(self):
        '''
            regresa la barra de navegacion y banner
        '''
        body_titulo = '''
            <body>

                <nav>
                    <ul>
                        <li><a href="#información_general">Información general </a></li>
                        <li><a href="#puertos">Puertos </a></li>
                        <li><a href="#dns_dumpster">DNS Dumpster </a></li>
                        <li><a href="#robtex">Robtex </a></li>
                        <li><a href="#bibliotecas,_frameworks,_lenguajes">Bibliotecas, Frameworks, Lenguajes </a></li>
                        <li><a href="#cifrados">Cifrados </a></li>
                        <li><a href="#plugins">Plugins </a></li>
                        <li><a href="#archivos">Archivos </a></li>
                        <li><a href="#google">Google </a></li>
                        <li><a href="#bing">Bing </a></li>
                        <li><a href="#headers">Headers </a></li>
                        <li><a href="#cve">CVE </a></li>
                        <li><a href="#vulnerabilidades">Vulnerabilidades </a></li>
                        <li><a href="#vulnerabilidades_por_página">Vulnerabilidades por página </a></li>
                        <li><a href="#posibles_vulnerabilidades">Posibles Vulnerabilidades </a></li>
                        <li><a href="#explotación">Explotación </a></li>
                    </ul>
                </nav>
                <!-- Header -->
                <div class="contenedor-titulo">
                    <h1 class="titulo">
                        UNAM-CERT Malphas
                    </h1>
                </div>
        '''
        return body_titulo

    def get_body_subtitulo_reporte(self):
        '''
            regresa el subtitulo del reporte en este caso sitio con su fecha
        '''
        body_subtitulo_reporte = '''
            <h2 class="subtitulo" style="text-align: center;">
                REPORTE DEL SITIO {0}
            </h2>
            <!-- Fecha del analisis-->
            <h4 class="subtitulo" style="text-align: center;">
                {1}
            </h4>
            <hr class="linea-doble-divisora">
        '''.format(self.sitio, self.fecha)
        return body_subtitulo_reporte

    def get_body_categoria(self, categoria):
        '''
            agrega la etiqueta categoria

            Parametros
            ----------
            categoria : str
                nombre de la categoria
        '''
        body_categoria = '''
            <h3 class="categoria">
                {0}
            </h3>
            <hr class="linea-divisora">
        '''.format(categoria)
        return body_categoria

    def get_body_titulo_grafica(self, titulo):
        '''
            agrega la etiqueta de titulo a la grafica

            Parametros
            ----------
            titulo : str
                titulo de la grafica
        '''
        body_titulo = '''
            <h3 class="subtitulo" id="{0}">
                {1}
            </h3>
        '''.format(titulo.replace(" ","_").lower(),titulo)
        return body_titulo

    def get_body_grafica(self, grafica):
        '''
            agrega el espacio para mostrar le iframe de la grafica

            Parametros
            ----------
            grafica : str
                ruta de la grafica
        '''
        body_categoria = '''
            <div class="contenedor-grafica">                           
                </iframe>                           
                    <iframe src="{0}" width="100%" height="400">
                </iframe>
            </div>
        '''.format(grafica)
        return body_categoria

    def get_body_descripcion(self, grafica, cabeceras, datos):
        '''
            agrega una tabla que muestra los datos analizados por anteriores modulos

            Parametros
            ----------
            grafica : int
                indica si es necesario agregar un formato diferente de tabla (sin uso)
            cabeceras : array
                lista de cadenas que forma la cabecera de la tabla
            datos : array
                datos que se mostraran debajo de la cabecera

        '''
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
        '''
            funcion que sirve para iterar los analisis e ir agregando etiquetas
        '''
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
        '''
            funcion integredora de etiquetas que forman el body
        '''
        body = self.get_body_titulo()+self.get_body_subtitulo_reporte()+self.get_body_analisis()
        return body

    def get_footer(self):
        '''
            regresa el footer
        '''
        footer = '''<hr class="linea-doble-divisora">
            <div class="contenedor-titulo"">
                <img src="{{ url_for('static', filename='img/unam_negro.png') }}"
                width="56px" height="56px" style="vertical-align: middle; border: 0; max-width: 100%; padding-right: 4px; -webkit-filter: invert(1); filter: invert(1);">
                <h4 style="line-height: 80px; font-family: sans-serif; color:#FFFFFF; margin: 0; padding: 0; display: inline; ">
                    Coordinación de Seguridad de la Información
                </h4>
                <img src="{{ url_for('static', filename='img/cert_negro.png') }}"
                    width="56px" height="56px" style="vertical-align:middle; border: 0; max-width: 100%; -webkit-filter: invert(1); filter: invert(1);">
            </div>
        </body>

        </html>'''
        return footer

    def crear_reporte(self):
        '''
            crea el documento html con todas las secciones creadas previamente
        '''
        reporte_html = self.get_html()+self.get_head()+self.get_body()+self.get_footer()
        ruta = "./templates/reporte.html"
        with open(ruta,"w") as reporte:
            reporte.write(reporte_html)
            
def execute(paremetros):
    '''
        lanza la ejecucion del reporte
    '''
    reporte = Reporte(paremetros)
    reporte.crear_reporte()
    print("Reporte creado")