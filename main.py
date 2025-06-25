# main.py
import sys
import os

# Add the src directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'src')))

if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "server":
            from rsa_messenger.server import main
            main()
        elif sys.argv[1] == "client":
            from rsa_messenger.client import main
            main()
        else:
            print("Invalid argument. Use 'server' or 'client'.")
    else:
        print("Please provide an argument: 'server' or 'client'.")
