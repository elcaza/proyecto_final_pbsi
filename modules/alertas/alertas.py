import smtplib
import ssl
from datetime import datetime
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from modules import strings

class Correo():
    def __init__(self, parametros):
        self.set_subject(parametros)
        self.set_sitios(parametros)
        self.set_fecha(parametros)
        self.correo_contrasena = strings.CORREO_CONTRASENA
        self.correo_remitente = strings.CORREO_REMITENTE
        self.correo_destinatario = strings.CORREO_DESTINATARIO
        self.correo_mensaje_texto = ""
        self.correo_mensaje = MIMEMultipart()
        self.contexto = ssl.create_default_context()

    def set_subject(self, parametros):
        if "subject" in parametros:
            self.subject = parametros["subject"]
        else:
            self.subject = "Alerta"

    def set_sitios(self, parametros):
        self.sitios = []
        if "sitios" in parametros:
            for sitio in parametros["sitios"]:
                self.sitios.append(sitio)

    def set_fecha(self, parametros):
        if "fecha" in parametros:
            self.fecha = parametros["fecha"]
        else:
            self.fecha = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    def get_subject(self):
        return self.subject

    def get_sitios(self):
        return self.sitios

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
            </head>
        """
        return head

    def get_body_inicio(self):
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

    def get_body_sitio(self, sitio):
        sitio_vulnerable = """
                            <tr>    
                                <td style="padding: 0; margin: 0; padding-left: 10px; padding-top: 20px;">
                                    Sitio
                                </td>
                                <td style="padding: 0; margin: 0;  padding-left: 10px; padding-top: 20px;">
                                    {0}
                                </td>
                            </tr>
            """.format(sitio)
        return sitio_vulnerable

    def get_body_motivo(self, motivo):
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
        self.correo_mensaje  = MIMEMultipart()
        self.correo_mensaje.attach(MIMEText(self.correo_mensaje_texto,"html"))
        self.correo_mensaje["From"] = self.correo_remitente
        self.correo_mensaje["To"] =  self.correo_destinatario
        self.correo_mensaje["Subject"] = self.subject

    def enviar_correo(self):
        with smtplib.SMTP_SSL("smtp.gmail.com",context=self.contexto) as correo:
            correo.login(self.correo_remitente, self.correo_contrasena)
            correo.sendmail(self.correo_remitente, self.correo_destinatario, self.correo_mensaje.as_string())

def execute(paremetros):
    correo = Correo(paremetros)
    correo.crear_mensaje_sitio()
    correo.crear_cabecera()
    correo.enviar_correo()
    print("Mensaje enviado")