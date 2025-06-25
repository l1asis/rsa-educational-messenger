# RSA-Powered Messenger for Educational Purposes

## Disclaimer

**This project is for educational purposes only.**

This application was developed during my school time in Germany to complement a presentation about the RSA algorithm. The primary goal is to provide a hands-on tool for understanding RSA and related number theory concepts. It is **not** a secure communication tool and should not be used for sensitive information.

This project is a chat application that uses the RSA algorithm for encryption. It was created to make it easier to understand the RSA algorithm and other topics related to it. It includes a client with a graphical user interface (GUI) built using `tkinter` and a server to manage connections and message relay. The application also provides several cryptographic and number-theoretic tools to play around with.

## Features

- **RSA Encryption Demonstration**: Messages are encrypted using a basic RSA implementation, demonstrating how public-key cryptography works.
- **Client-Server Architecture**: A central server handles user connections, message broadcasting, and user management.
- **User-Friendly GUI**: The client application features a `tkinter`-based GUI for ease of use, including panels for chat, user profiles, and various cryptographic tools.
- **Cryptographic Toolkit**: The application includes a suite of tools for number theory and cryptography enthusiasts:
  - **Prime Number Generator**: Find random, next, or previous prime numbers.
  - **Prime Factorization Tool**: Factorize large numbers and estimate the time required.
  - **RSA Key Generator**: Create your own RSA public and private key pairs.
  - **Cipher Inspector**: View and analyze encrypted messages.
- **User Management**: The server includes a control panel to approve, ban, or kick users.
- **Internationalization**: Support for multiple languages with translations managed in a centralized file.

## How to Run

### Prerequisites

- Python 3.x
- `sympy` library (`pip install sympy`)
- `faker` library (`pip install Faker`)

### Running the Server

1.  Navigate to the project directory.
2.  Run the server:

    ```bash
    python main.py server
    ```
    Alternatively:
    ```bash
    python -m src.rsa_messenger.server
    ```

3.  The server control panel will open, and it will start listening for client connections on `127.0.0.1:8080`.

### Running the Client

1.  Navigate to the project directory.
2.  Run the client:

    ```bash
    python main.py client
    ```
    Alternatively:
    ```bash
    python -m src.rsa_messenger.client
    ```

3.  The client application will open. Enter the server IP and port to connect.

## Running Module Tests

Some modules contain self-tests within an `if __name__ == "__main__":` block. You can run these tests to verify the functionality of individual components.

I will add more tests in the future, but currently, they are limited to basic functionality checks. I also plan to implement more comprehensive unit tests using `unittest` or `pytest`.

For example, you can test the `crypto.py` and `utils.py` modules:

```bash
python -m src.rsa_messenger.crypto
python -m src.rsa_messenger.utils
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
