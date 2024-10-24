import os
import sys

class NetScanX:

    def banner(self):
        banner = '''

    ███╗   ██╗███████╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗██╗  ██╗
    ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║╚██╗██╔╝
    ██╔██╗ ██║█████╗     ██║   ███████╗██║     ███████║██╔██╗ ██║ ╚███╔╝ 
    ██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██╔══██║██║╚██╗██║ ██╔██╗ 
    ██║ ╚████║███████╗   ██║   ███████║╚██████╗██║  ██║██║ ╚████║██╔╝ ██╗
    ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝
                                                                         
            '''
        print(banner)

    def details(self):
        details = """
        NetScanX  - Netverks analyse verktøy
        laget av Aldar Ali
        https://github.com/AldarAli/netScanX
        version: 1.0
        """
        print(details)

    def display_menu(self):
        menu = """
        1. SCANNING  2. REKOGNOSERING  3. OPPDAGELSE  4. AVSLUTT
        
        """
        print(menu)

    def run(self):
        while True:
            try:
                self.banner()
                self.details()
                self.display_menu()
                choice = input("\nVelg en alternativ [1-4]: ")

                if choice == "1":
                    print("\n[*] Scanning")
                elif choice == "2":
                    print("\n[*] Rekognosering")
                elif choice == "3":
                    print("\n[*] Oppdagelse")
                elif choice == "4":
                    print("\n[+] Avslutt")
                    sys.exit(0)
                else:
                    print("\n[-] ugyldig alternativ")
                    input("\nklikk Enter for å fortsette...")

            except Exception as e:
                print(f"\n[-] An error occurred: {e}")
                input("\nPress Enter to continue...")


if __name__ == '__main__':
    NetScanX().run()







    