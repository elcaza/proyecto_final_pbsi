import smtplib
import ssl
from datetime import datetime
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from os import path, pardir
import json

class Correo():
    '''
        Clase que configura los datos para el envio de correos

        por cada envio se crean las etiquetas del html incluyendo el css

        .........
        
        Atributos
        ---------
        correo_mensaje_texto : str
            guarda el body del html
        
        correo_mensaje : MIMEMultipart
            formato del correo que permite interactuar con el envio del mensaje

        contexto : SSLContext
            contexto para el uso de ssl

        correo_contrasena : str
            contraseña de la cuenta que envia correos

        correo_remitente : str
            nombre de la cuenta que envia correos

        correo_destinatario : str
            nombre del correo al cual se enviaran los correos

        subject : str
            nombre del asunto

        paginas : array
            lista de paginas que contienen diccionarios para la extraccion del motivo y estado

        fecha : str
            fecha del envio del correo

        Metodos
        -------
        set_datos_correo():
            obtiene las credenciales de la cuenta abriendo el archivo de configuracion strings.json

        set_subject(parametros):
            extrae de los parametros el asunto del correo

        set_paginas(parametros):
            extrae de los parametros la evaluacion de las paginas

        set_fecha(parametros):
            extrae de los parametros la fecha del analisis

        get_subject():
            regresa el asunto

        get_paginas():
            regresa las paginas

        get_fecha():
            regresa la fecha

        crear_mensaje_pagina():
            carga el header y el body por todas las paginas

        get_html():
            crea la etiqueta html

        get_head():
            crea el header necesario para el correo

        get_body_inicio():
            crea el banner del correo

        get_body_fin():
            crea el footer del correo

        get_body_pagina(pagina):
            crea dentro de la seccion  de la pagina el nombre de la pagina

        get_body_motivo(motivo):
            crea dentro de la seccion de la pagina el motivo del mensaje

        get_body_estado(estado):
            crea dentro de la seccion de la pagina el estado obtenido vulnerable, no vulnerable o posible vulnerable de la pagina

        get_body_salto():
            crea un salto de linea dentro la seccion del sitio

        crear_cabecera():
            crea y configura el objeto del correo con el remitente, destinatario y asunto

        enviar_correo():
            envia el correo electronico de la cuenta remitente al destinatario

    '''
    def __init__(self, parametros):
        self.set_subject(parametros)
        self.set_paginas(parametros)
        self.set_fecha(parametros)
        self.set_datos_correo()
        self.correo_mensaje_texto = ""
        self.correo_mensaje = MIMEMultipart()
        self.contexto = ssl.create_default_context()

    def set_datos_correo(self):
        '''
            obtiene las credenciales de la cuenta abriendo el archivo de configuracion strings.json
        '''
        ruta = path.abspath(path.join(path.dirname(__file__), pardir)) + "/strings.json"
        with open (ruta, "r") as json_strings:
            strings = json.load(json_strings)
            
        self.correo_contrasena = strings["CORREO_CONTRASENA"]
        self.correo_remitente = strings["CORREO_REMITENTE"]
        self.correo_destinatario = strings["CORREO_DESTINATARIO"]

    def set_subject(self, parametros):
        '''
            extrae de los parametros el asunto del correo

            Parametros
            ----------
            parametros : dict
        '''
        if "subject" in parametros:
            self.subject = parametros["subject"]
        else:
            self.subject = "Alerta"

    def set_paginas(self, parametros):
        '''
            extrae de los parametros la evaluacion de las paginas

            Parametros
            ----------
            parametros : dict
        '''
        self.paginas = []
        if "paginas" in parametros:
            for pagina in parametros["paginas"]:
                self.paginas.append(pagina)

    def set_fecha(self, parametros):
        '''
            extrae de los parametros la fecha del analisis

            Parametros
            ----------
            parametros : dict
        '''
        if "fecha" in parametros:
            self.fecha = parametros["fecha"]
        else:
            self.fecha = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    def get_subject(self):
        '''
            regresa el asunto

            Parametros
            ----------
        '''
        return self.subject

    def get_paginas(self):
        '''
            regresa las paginas

            Parametros
            ----------
        '''
        return self.paginas

    def get_fecha(self):
        '''
            regresa la fecha

            Parametros
            ----------
        '''
        return self.fecha

    def crear_mensaje_pagina(self):
        '''
            carga el header y el body por todas las paginas

            itera sobre las paginas para extraer el motivo y el estado individual
            el cual es usado como parametro para las funciones de get_body_motivo y get_body_estado
            de esta forma se crea el cuerpo

            une el html, header, cuerpo 
        '''
        self.correo_mensaje_texto = self.get_html()+self.get_head()+self.get_body_inicio()
        for pagina in self.paginas:
            if pagina["pagina"] != "":
                pagina_vulnerable = self.get_body_pagina(pagina["pagina"])
            else:
                pagina_vulnerable = ""
            motivo = self.get_body_motivo(pagina["motivo"])
            estado = self.get_body_estado(pagina["estado"])
            salto = self.get_body_salto()
            self.correo_mensaje_texto += pagina_vulnerable+motivo+estado+salto
        self.correo_mensaje_texto += self.get_body_fin()

    def get_html(self):
        '''
            crea la etiqueta html

            Parametros
            ----------
        '''
        html = """
        <html xmlns="http://www.w3.org/1999/xhtml" xmlns:o="urn:schemas-microsoft-com:office:office"
                style="width: 100% ;font-family: sans-serif; padding: 0; margin: 0;">
        """
        return html

    def get_head(self):
        '''
            crea el header necesario para el correo
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
            </head>
        """
        return head

    def get_body_inicio(self):
        '''
            crea el banner del correo
        '''
        body_inicio = """
            <body style="margin: 0; padding: 0;">
                <div style="background-color:#EEEEEE; ">
                    <div style="background-color:#044767; width:600px; margin: auto;">
                        <h1 style="line-height: 80px; text-align: center;font-size: 36px; font-family: sans-serif; color:#FFFFFF;  margin: 0; padding: 0;">
                            UNAM CERT
                        </h1>
                    </div>
                    <div style="background-color: #FFFFFF;width: 600px; margin: auto;">
                        <table width="100%" cellspacing="0" cellpadding="0"">
                                <tr> 
                                    <td align=" left" style="padding: 0; margin: 0; padding-top: 40px; padding-bottom: 20px;">
                                        <h3 style="margin: 0; padding: 0; padding-left: 10px ;line-height: 22px; font-family: sans-serif; font-size: 18px; font-style: normal; font-weight: bold; color:#333333;">
                                            Alerta 
                                        </h3>
                                    </td>
                                    <td align=" left" style="padding: 0; margin: 0; padding-top: 40px; padding-bottom: 20px;">
                                        <h3 style="margin: 0; padding: 0; padding-left: 10px ;line-height: 22px; font-family: sans-serif; font-size: 18px; font-style: normal; font-weight: bold; color:#333333;">
        """

        fecha = """
        {0} 
                                        </h3>
                                    </td>
                                </tr>
        """.format(self.fecha)
        return body_inicio+fecha

    def get_body_fin(self):
        '''
            crea el footer del correo
        '''
        body_fin = """
                        </table>
                    </div>
                    <div style="background-color:#044767; width: 600px; margin: auto; text-align: center;">
                        <img src="https://congreso.seguridad.unam.mx/2016/sites/default/themes/theme2016/images/unam_negro.png" width="56px" height="56px" style="vertical-align: middle; border: 0; max-width: 100%; padding-right: 4px;">
                        <h4 style="line-height: 80px; font-family: sans-serif; color:#FFFFFF; margin: 0; padding: 0; display: inline;">
                            Coordinación de Seguridad de la Información
                        </h4>
                        <img src="https://congreso.seguridad.unam.mx/2016/sites/default/themes/theme2016/images/cert_negro.png" width="56px" height="56px" style="vertical-align:middle; border: 0; max-width: 100%;">
                    </div>
                </div>
            </body>
            </html>
        """
        return body_fin

    def get_body_pagina(self, pagina):
        '''
            crea dentro de la seccion de la pagina el nombre de la pagina

            en caso de que resultado fuera por sitio, cambio el titulo por Sitio y pinta el titulo
            
            Parametros
            ----------
            pagina : str
        '''
        titulo = "Pagina"
        if pagina.startswith("sitio "):
            titulo = "Sitio"
            pagina = pagina.replace("sitio ","")
        pagina_vulnerable = """
                            <tr>    
                                <td style="padding: 0; margin: 0; padding-left: 10px; padding-top: 20px;">
                                    {0}
                                </td>
                                <td style="padding: 0; margin: 0;  padding-left: 10px; padding-top: 20px;">
                                    {1}
                                </td>
                            </tr>
            """.format(titulo, pagina)
        return pagina_vulnerable

    def get_body_motivo(self, motivo):
        '''
            crea dentro de la seccion de la pagina el motivo del mensaje

            itera por cada salto de linea del motivo y crea un parrafo por cada iteracion

            Parametros
            ----------
            motivo : str
        '''
        motivos = """
                            <tr>
                                <td style="padding: 0; margin: 0; padding-left: 10px; padding-top: 20px;">
                                    Motivo
                                </td>
                                <td style="padding: 0; margin: 0;  padding-left: 10px; padding-top: 20px;">

                """
        for seccion in motivo.split("\n"):
            motivos += "<p>{0}</p>".format(seccion)

        motivos += """
                                      </td>
                            </tr>
            """
        return motivos

    def get_body_estado(self, estado):
        '''
            crea dentro de la seccion de la pagina el estado obtenido vulnerable, no vulnerable o posible vulnerable de la pagina

            Parametros
            ----------
            estado : str
        '''
        estado = """
                                <tr>
                                    <td style="padding: 0; margin: 0; padding-left: 10px; padding-top: 20px;">
                                        Estado
                                    </td>
                                    <td style="padding: 0; margin: 0;  padding-left: 10px; padding-top: 20px;">
                                        {0}
                                    </td>
                                </tr>
            """.format(estado)
        return estado

    def get_body_salto(self):
        '''
            crea un salto de linea dentro la seccion del sitio
        '''
        salto = """
                                <tr>
                                    <td style="padding: 0; margin: 0;  padding-left: 10px; padding-top: 5px;">
                                        <hr>
                                    </td>
                                    <td style="padding: 0; margin: 0; padding-top: 5px; padding-right: 10px;">
                                        <hr>
                                    </td>
                                </tr>
            """
        return salto

    def crear_cabecera(self):
        '''
            crea y configura el objeto del correo con el remitente, destinatario y asunto
        '''
        self.correo_mensaje  = MIMEMultipart()
        self.correo_mensaje.attach(MIMEText(self.correo_mensaje_texto,"html"))
        self.correo_mensaje["From"] = self.correo_remitente
        self.correo_mensaje["To"] =  self.correo_destinatario
        self.correo_mensaje["Subject"] = self.subject

    def enviar_correo(self):
        '''
            envia el correo electronico de la cuenta remitente al destinatario
        '''
        with smtplib.SMTP_SSL("smtp.gmail.com",context=self.contexto) as correo:
            correo.login(self.correo_remitente, self.correo_contrasena)
            correo.sendmail(self.correo_remitente, self.correo_destinatario, self.correo_mensaje.as_string())

def execute(paremetros):        
    '''
        lanza el envio del correo e imprime en consola el "Mensaje enviado"

        Parametros
        ----------
        paremetros : dict
    '''
    correo = Correo(paremetros)
    correo.crear_mensaje_pagina()
    correo.crear_cabecera()
    correo.enviar_correo()
    print("Mensaje enviado")