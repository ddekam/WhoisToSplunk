#!/usr/bin/env python3
"""
Script Name: main.py
Description: Queries information on domains
Author: Dayton Dekam
Date: 2025-05-17
"""

import argparse
import logging
import sys

from module.whois_query import *
from module.packet_processing import *
from module.send_to_splunk import *

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )

def parse_args():
    parser = argparse.ArgumentParser(description="Monitor DNS queries and stores whois information in Splunk")
    parser.add_argument(
        "--log", action="store_true", help="Enable logging output"
    )
    return parser.parse_args()

def choose_interface():
    interfaces = get_if_list()

    print("Available network interfaces:")
    for idx, iface in enumerate(interfaces):
        print(f"{idx + 1}: {iface}")

    while True:
        try:
            choice = int(input("Select the interface to use for monitoring (enter number): "))
            if 1 <= choice <= len(interfaces):
                selected_iface = interfaces[choice - 1]
                print(f"Selected interface: {selected_iface}")
                return selected_iface
            else:
                print("Invalid choice. Try again.")
        except ValueError:
            print("Please enter a valid number.")

def main():
    args = parse_args()

    if args.log:
        setup_logging()
        logging.info("Logging is enabled")
    else:
        # If logging is not enabled, disable all logging below WARNING
        logging.disable(logging.WARNING)
        print("logging disabled")

    interface = choose_interface()
    if not interface:
        print("No valid interface selected. Exiting.")
        sys.exit(1)
    logging.info("Selected interface: %s", interface)

    sniff(filter="udp port 53", iface=interface, prn=process_packet, store=False)

if __name__ == "__main__":
    try:
        main()

    except Exception as e:
        if logging.getLogger().isEnabledFor(logging.INFO):
            logging.exception("An unexpected error occurred: %s", e)
        else:
            print(f"An error occurred: {e}")
        sys.exit(1)
