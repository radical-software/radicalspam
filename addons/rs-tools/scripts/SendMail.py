#!/usr/bin/python
# -*- coding: utf-8 -*-

__version__ = "0.1"

import sys
import smtplib
import os
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from optparse import OptionParser
from string import Template
from ConfigParser import ConfigParser, ParsingError

# ------------------------------------------------------------------------------
# Envoi de mail avec ou sans pièces jointe
# Destinataires multiples
# Corps du mail en direct ou en provenance d'un fichier
# Le fichier pour le corps du mail peut être un template avec des variables ($VAR)
# Les variables peuvent être fournies avec -c ou --callback VAR1=value, VAR2=value
# 1 ou plusieurs pièces jointes
# ------------------------------------------------------------------------------

"""
TODO: Evolutions possibles :
- Internationalisation : options, fichier config, tous messages
- Chemin d'un répertoire contenant tous les fichiers à envoyer
- Option de création d'archives tar ou zip des fichiers à envoyer
- Utilisation de logging

TODO: Gestion des exceptions détaillés
    exception SMTPException
    exception SMTPServerDisconnected
    exception SMTPResponseException
    exception SMTPSenderRefused
    exception SMTPRecipientsRefused + attribut recipients (liste destinataire refusé)
    exception SMTPDataError
    exception SMTPConnectError
    exception SMTPHeloError
"""
def send( sender=None, recipients=[], subject=None, body=None, body_file=None, files=[], smtp_server='127.0.0.1', smtp_port=25, smtp_debug=False, smtp_timeout=-1, template_var=None ):

    if sender is None: raise Exception("sender not found.")

    if len(recipients) < 1: raise Exception("recipients not found.")

    if body is None and body_file is None: raise Exception("body or body file not found")

    is_multipart = False

    if len(files) > 0: is_multipart = True

    msg = None

    body_mail = None

    if not body_file is None:
        if not os.path.exists(body_file):
            print "body file %s not found" % body_file
            sys.exit(1)

        fp = open(body_file, 'rb')
        body_txt = None
        if len(template_var) > 0:
            tmpl = Template(fp.read())
            body_txt = tmpl.substitute(template_var)
        else:
            body_txt = fp.read()

        body_mail = MIMEText(body_txt)
        fp.close()
    else:
        if body is None: body = '-----------------'
        body_mail = MIMEText('body')

    if is_multipart:
        msg = MIMEMultipart()
        msg.attach(body_mail)
    else:
        msg = body_mail

    msg['From'] = sender
    msg['To'] = ', '.join(recipients)
    msg['Subject'] = subject

    #X-Mailer: RadicalSpam-Notify-From-Python
    msg['X-Mailer'] = 'RadicalSpam-Notify-From-Python'

    if is_multipart:
        for file in files:
            if not os.path.exists(file):
                print "file %s not found" % file
                sys.exit(1)

            fp = open(file, 'rb')
            msg_file = MIMEBase('application', 'octet-stream')
            msg_file.set_payload(fp.read())
            fp.close()
            encoders.encode_base64(msg_file)
            msg_file.add_header('Content-Disposition', 'attachment', filename=os.path.basename(file))
            msg.attach(msg_file)

    try:
        #Changed in version 2.6: timeout  was added : timeout=???
        #smtp_timeout
        server = smtplib.SMTP(smtp_server, smtp_port)
        if smtp_debug: server.set_debuglevel(1)
        server.sendmail(sender, recipients, msg.as_string())
        server.quit()

    except smtplib.SMTPException, err:
        print "SMTPException : %s " % str(err)
        sys.exit(1)
        #raise Exception("SMTPException : " + str(err))

    return True

def vararg_callback(option, opt_str, value, parser):

    assert value is None
    value = {}

    def floatable(str):
        try:
            float(str)
            return True
        except ValueError:
            return False

    for arg in parser.rargs:
        if arg[:2] == "--" and len(arg) > 2:
            break
        if arg[:1] == "-" and len(arg) > 1 and not floatable(arg):
            break
        key, val = arg.split('=')
        value[key]=val
        #value.append(arg)

    #del parser.rargs[:len(value)]
    setattr(parser.values, option.dest, value)

def options_process():

    usage="""\

Send a mail with or not with attach files.
Usage: %prog [options]
"""

    parser = OptionParser(usage=usage, version="%prog " + str(__version__))

    parser.add_option("-s", "--sender", dest="sender",
                  default=None,
                  help="Mail Sender")

    parser.add_option("-r", "--recipients", dest="recipients",
                  default=None,
                  help="Mail Recipients (separate by ',')")

    parser.add_option("--subject", dest="subject",
                  default=None,
                  help="Mail Subject")

    parser.add_option("--body", dest="body",
                  default=None,
                  help="Mail Body Text")

    parser.add_option("--body-file", dest="body_file",
                  default=None,
                  help="Mail Body from File")

    parser.add_option("--files", dest="files",
                  default=None,
                  help="Mail Files (separate by ',')")

    parser.add_option("--smtp-server", dest="smtp_server",
                  default='127.0.0.1',
                  help="Smtp Server (default 127.0.0.1)")

    parser.add_option("-p", "--smtp-port", dest="smtp_port",
                  default=25,
                  help="Smtp Server Port")

    parser.add_option("-d", "--debug", dest="debug",
                  default=False,
                  action="store_true",
                  help="Active le mode debug de la transaction SMTP")

    parser.add_option("--config-path", dest="config_path",
                  default="/etc/radicalspam-python.conf",
                  help="Fichier de configuration. [default: %default]")

    parser.add_option("--config-load", dest="config_load",
                  default=False,
                  action="store_true",
                  help="Charge les parametres a partir du fichier de configuration")

    parser.add_option("--config-section", dest="config_section",
                  default=None,
                  help="Cherche les parametres de config dans cette section, sinon dans [main]")

    parser.add_option("-c", "--callback", dest="template_var",
                  default={},
                  action="callback", callback=vararg_callback,
                  help="Options for mail template")

    return parser

def config_process(config_path):
    """
    Charge un fichier de configuration de type .ini
    Renvoit un ConfigParser
    """
    try:
        config = ConfigParser()
        config.readfp(open(config_path, 'r'))
        return config
    except ParsingError, err:
        raise Exception("Parsing configuration error: %s." % err)

if __name__ == '__main__':

    parser = options_process()
    opts, args = parser.parse_args()

    if not opts.config_load:
        if not opts.sender or not opts.recipients:
            parser.print_help()
            sys.exit(1)

    opt_files = []
    if not opts.files is None: opt_files = opts.files.split(',')

    mail_sender = opts.sender
    mail_recipients = opts.recipients
    mail_subject = opts.subject
    mail_body = opts.body
    mail_body_file = opts.body_file
    mail_server = opts.smtp_server
    mail_server_port = opts.smtp_port

    if opts.config_load:
        try:
            file_config = opts.config_path
            if os.path.exists(file_config):

                # Chargement des variables à partir du fichier de conf
                config = config_process(file_config)

                # Section par defaut
                section = 'main'

                if opts.config_section:
                    section = opts.config_section

                if not config.has_section(section):
                    print "La section %s du fichier de configuration %s n'existe pas" % (section, file_config)
                    sys.exit(1)

                if config.has_option(section, 'mail_sender'):
                    mail_sender = config.get(section, 'mail_sender')

                if config.has_option(section, 'mail_recipients'):
                    mail_recipients = config.get(section, 'mail_recipients')

                if config.has_option(section, 'mail_subject'):
                    mail_subject = config.get(section, 'mail_subject')

                if config.has_option(section, 'mail_body_file'):
                    mail_body_file = config.get(section, 'mail_body_file')

                if config.has_option(section, 'mail_server'):
                    mail_server = config.get(section, 'mail_server')

                if config.has_option(section, 'mail_server_port'):
                    mail_server_port = config.get(section, 'mail_server_port')

                #if config.has_option(section, 'mail_body'):
                #    mail_body = config.get(section, mail_body)
            else:
                print "Le fichier de configuration %s n'existe pas" % file_config
                sys.exit(1)

        except Exception, err:
            print str(err)
            exit(1)

    send(mail_sender,
         mail_recipients.split(','),
         mail_subject,
         mail_body,
         mail_body_file,
         opt_files,
         mail_server,
         mail_server_port,
         smtp_debug=opts.debug,
         template_var=opts.template_var)

    print "Send Message OK"

    sys.exit(0)
