import configparser
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formatdate


def send_request(message, subject, useremail=None):
    '''
    Send mail to admin and reply to user if usermail set
    '''

    config = configparser.ConfigParser()
    config.read('lxdconfig.conf')

    sender = config['smtp']['sender']
    to = config['smtp']['recipient']
    cc = useremail

    print("Sending email: " + message + " subject: " + subject)

    # Test message to json <html>\n<head></head>\n<body>\n<p>Hi!<br>This is test\n</p>\n</body>\n</html>
    content = MIMEText(message, 'html')

    try:
        if cc is not None:
            receivers = [cc] + [to]
        else:
            receivers = to
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = sender
        msg['To'] = to
        msg['Cc'] = cc
        msg["Date"] = formatdate(localtime=True)
        msg.attach(content)
        mailserver = smtplib.SMTP(config['smtp']['server'], config['smtp']['port'], timeout=40)
        mailserver.set_debuglevel(1)
        mailserver.ehlo()
        mailserver.starttls()
        mailserver.ehlo()
        mailserver.login(config['smtp']['login'], config['smtp']['password'])
        try:
            mailserver.send_message(msg, sender, receivers)
            print("Successfully sent email")
            return "Successfully sent email"
        except:
            print("Error: unable to send email")
            return "Error: unable to send email"
        finally:
            mailserver.quit()
    except smtplib.SMTPException:
        print("Error: unable to send email")
        return "Error: unable to send email"


def main():
    send_request('Test message', 'Test subject')


if __name__ == "__main__":
    main()
