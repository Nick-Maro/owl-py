# owl-py

A Python implementation of the Owl augmented PAKE protocol, based on the [Owl paper](https://eprint.iacr.org/2023/768.pdf).

##  Installation
(its not installable yet)

To install the package, run: 

```bash
pip install owl-py
```

Or install directly from the repository:

```bash
git clone https://github.com/yourusername/owl-py.git
cd owl-py
pip install -e .
```

### Dependencies

```bash
pip install cryptography
```

##  Features

- **Secure Password-Based Authentication**: Implements the OWL (Optimal Password Authenticated Key Exchange) protocol
- **Zero-Knowledge Proofs**: Password is never transmitted or revealed
- **Standard Elliptic Curves**: Support for P-256, P-384, P-521


### Setup

The client and server must use the same configuration of elliptic curve and server identity. The configuration object can be created as follows:

```python
from owl_common import Config, Curves

config = Config(
    curve=Curves.P256,
    serverId="example.com"
)
```

The possible values of `Curves` are:
- `Curves.P256` - NIST P-256 curve (recommended for most uses)
- `Curves.P384` - NIST P-384 curve (higher security)
- `Curves.P521` - NIST P-521 curve (maximum security)

This configuration can then be used to set up the client and server:

```python
from owl_client import OwlClient
from owl_server import OwlServer

client = OwlClient(config)
server = OwlServer(config)
```

### Messages

The Owl server and client use messages for input and output. Messages can be serialized to JSON with the `serialize()` method. Messages can be deserialized using the `deserialize()` method. This method takes either a dict object or its string representation and returns a message object or a `DeserializationError` if the input was not a valid message.

There are 6 message classes:

- **`RegistrationRequest`** - Contains values output by `OwlClient.register` and used by `OwlServer.register`
- **`UserCredentials`** - Contains user credentials to be stored permanently in the database alongside the username
- **`AuthInitRequest`** - Contains values output by `OwlClient.authInit` and used by `OwlServer.authInit`
- **`AuthInitialValues`** - Temporary values output by `OwlServer.authInit` and used by `OwlServer.authFinish` to be stored in the database alongside the username. After `OwlServer.authFinish` is complete, these values can be deleted
- **`AuthInitResponse`** - Contains values output by `OwlServer.authInit` and used by `OwlClient.authFinish`
- **`AuthFinishRequest`** - Contains values output by `OwlClient.authFinish` and used by `OwlServer.authFinish`


##  Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a branch for your feature (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request


## License

This project is released under the MIT License. See the [LICENSE](LICENSE) file for details.

##  Acknowledgments

- Based on the [Owl paper](https://eprint.iacr.org/2023/768.pdf)
- Inspired by the TypeScript implementation [owl-ts](https://github.com/henry50/owl-ts)


**Made with ❤️ in Python**