# RSA-Powered Messenger (Educational Project)

A `tkinter`-based chat application built to demonstrate the RSA encryption algorithm and related number theory concepts. This project was developed for a school presentation in Germany, aiming to provide a hands-on tool for understanding RSA in practice.

**⚠️ Important Disclaimer: This application is for educational purposes only and is NOT a secure communication tool. Do not use it for sensitive information.**

## Features

- **RSA Encryption Demonstration**: See RSA in action! Messages are encrypted using a basic RSA implementation, showing how public-key cryptography works.
- **Client-Server Architecture**: Features a central server handling user connections, message broadcasting, and user management.
- **User-Friendly GUI**: The `tkinter`-based client provides an intuitive interface with dedicated panels for chat, user profiles, and cryptographic tools.
- **Integrated Cryptographic Toolkit**: Explore number theory and cryptography with built-in tools:
  - **Prime Number Generator**: Find random, next, or previous prime numbers.
  - **Prime Factorization Tool**: Factorize large numbers and estimate the time required.
  - **RSA Key Generator**: Create your own RSA public and private key pairs.
  - **Cipher Inspector**: View and analyze encrypted messages.
- **Server User Management**: The server includes a control panel to approve, ban, or kick users.
- **Localizable Interface**: Supports multiple languages with translations managed in a centralized file.

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
