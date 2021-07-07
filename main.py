import nmap
import os
import time
scan = nmap.PortScanner()


def nslookup():
    domaine = input("Enter a domain (Exemple : google.com) : ")
    print(os.system('nslookup ' + domaine))
    time.sleep(2)
    back = input("\nWrite 'back' to return to the main menu : ")
    if back == 'back':
        main()


def tracert():
    domaineorIpadresse = input("Enter a domain or IP adresse(Exemple : google.com or 192.168.1.1) : ")
    print(os.system('tracert ' + domaineorIpadresse))
    time.sleep(2)
    back = input("\nWrite 'back' to return to the main menu : ")
    if back == 'back':
        main()


def whois():
    domaine = input("Enter a domain (Exemple : google.com) : ")
    print(os.system('whois ' + domaine))
    time.sleep(2)
    back = input("\nWrite 'back' to return to the main menu : ")
    if back == 'back':
        main()


def vulnscan():
    print("Welcome to the Vulnerabilities Scanner")
    ip = input("\nPlease Enter IP: ")
    print(os.system('nmap -sV --script=vulscan.nse ' + ip))
    back = input("\nWrite 'back' to return to the main menu : ")
    if back == 'back':
        main()


def nmap():
    print("Welcome to the network Scanner !")
    ip = input("\nPlease enter IP: ")
    print("This process may take some time please wait")
    scan.scan(ip, '1-1024')
    print(scan.scaninfo())
    print(scan[ip]['tcp'].keys())
    back = input("\nWrite 'back' to return to the main menu : ")
    if back == 'back':
        main()


def startmetasploit():
    print("Metasploit must be installed on your machine")
    os.system('msfconsole')


def contact():
    print("Coded by tchikaModz")
    print("Contact: \nDiscord : [LTMT]tchikaModz#0001\nInstagram : tchikaModz")
    n = input("Write 'back' to return to the main menu : ")
    if n == 'back':
        main()
    else:
        print("Please write 'back' return to the main menu")
        time.sleep(3)
        os.system('clear')
        contact()


def cmdforuserwin():
    print("This tool was made for windows users (cmd)\n")
    n = input("1- Ipconfig\n2- nslookup\n3- tracert : ")
    if n == '1':
        os.system('ipconfig')
    if n == '2':
        nslookup()
    if n == '3':
        tracert()


def cmdlinux():
    print("This tool was made for noob linux users \n")
    n = input("1- Ifconfig\n2- sl\n3- nslookup\n4- whois")
    if n == '1':
        os.system('ifconfig')
    if n == '2':
        os.system('apt install sl')
        os.system('sl')
    if n == '3':
        nslookup()
    if n == '4':
        whois()


def main():
    n = input("Welcome To my hacking tool\n1- Network scanner\n2- Vulnerabilities Scanner\n3- Start metasploit(If installed)\n4- Cmd command for user windows\n5- Command linux for noob\n6- Contact\nYour choose : ")
    if n == '1':
        nmap()
    if n == '2':
        vulnscan()
    if n == '3':
        startmetasploit()
    if n == '4':
        cmdforuserwin()
    if n == '5':
        cmdlinux()
    if n == '6':
        contact()
    else:
        print("Please choose a tool")


if __name__ == "__main__":
    main()

