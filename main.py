from modules.banner import show_banner
from modules.loading import loading
from modules.menu import main_menu
from modules.target import set_target
from modules.subdomain import subdomain_enum

# Modules
from modules.nmap import nmap_menu
from modules.whois_lookup import whois_lookup
from modules.dns_lookup import dns_lookup
from modules.geolocation import geolocation
from modules.report import generate_report


def main():

    show_banner()
    loading()

    while True:

        option = main_menu()

        if option == "target":
            set_target()

        elif option == "nmap":
            nmap_menu()

        elif option == "whois":
            whois_lookup()

        elif option == "dns":
            dns_lookup()

        elif option == "geo":
            geolocation()

        elif option == "subdomain":
            subdomain_enum()    

        elif option == "report":
            generate_report()

        elif option == "exit":

            print("\nThank you for using RAT.")
            break


if __name__ == "__main__":
    main()
