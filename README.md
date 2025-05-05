# SteganoRust Documentation

SteganoRust is a Rust library for steganography that hides messages inside PNG images using the LSB (Least Significant Bit) technique. It features AES-256-GCM encryption and a database to track message storage locations.

## Project structure

``` bash
📁 src/
├── 📁 core/
│ ├──── 🧩 decoder.rs - 🕵️‍♂️ Extracts hidden messages from images
│ └└── 🧩 encoder.rs - ✍️ Inserts messages in PNG images
├─── 📁 crypto/
│ └─── 🔐 crypto.rs - 🛡️ Encryption and hashing utilities.
├─── 📁 formats/
│ └└─── 🗂️ header.rs - 🧾 Message metadata structure.
└─── 📁 utils/
    └─── 🗃️ index_db.rs - 🧮 SQLite database for message tracking.
```

# 🔧 **Core Components**

## 🧩 **Encoder** (`core/encoder.rs`)

The **StegoEncoder** is responsible for **inserting messages** into PNG images. The main features and capabilities of this component are detailed below:

### Encoder Features

* Configurable bit depth**: Use 1 to 3 Least Significant Bits (LSBs) per RGB channel to hide the message.
* Password protection**: AES-256-GCM encryption** can be optionally applied to protect the hidden message.
* Automatic distribution**: If the message is too large for a single image, it is automatically divided into multiple images.
* **Capacity monitoring**: Keeps track of the available space in each image, ensuring that the capacity limits of the images are not exceeded.

### Example of Use

Below is an example of how to initialize and use the **StegoEncoder** to hide messages in a series of PNG images:

``` rust
let encoder = StegoEncoder::new(
    2, // 2 bits per channel (RGB)
    Some(“password”.to_string()), // Optional password for encryption
    PathBuf::from(“index”) // Path to the index database.
);

// Hide messages in images within the directory
let results = encoder.encode_messages(&messages, Path::new(“./images”))?;
```

## 🧩 **Decoder** (`core/decoder.rs`)

The **StegoDecoder** is responsible for **extracting hidden messages** in PNG images. The main features and capabilities of this component are listed below:

### Decoder Features.

* Targeted retrieval**: Allows to extract specific messages using a unique identifier (ID).
* **Batch extraction**: Can retrieve all hidden messages in images at once.
* Integrity check**: Verifies the validity of messages by checking the hashes.
* **Transparent decryption**: Handles decryption of messages using AES, provided the correct password is supplied.

### Example of Use

Below is an example of how to initialize and use the **StegoDecoder** to extract messages from PNG images:

``` rust
let decoder = StegoDecoder::new(
    2, // Must match the bit depth used in the encryption.
    Some(“password”.to_string()), // Necessary if message was encrypted
    “index”.to_string() // Path to index database.
);

// Decode all hidden messages
let all_messages = decoder.decode_all_messages()?;      
```

# 📦 **Message Header in SteganoRust**

The **StegoHeader** defined in `src/formats/header.rs` is a crucial component of the **SteganoRust** steganography system. This header is prefixed to each message before being inserted into the image, and contains essential information for the correct retrieval and verification of the hidden message.

## 🏗️ **Header Structure**.

The header is a fixed 36-byte structure containing the following information:

| Field                        | Size    | Description                                                          |
|------------------------------|---------|----------------------------------------------------------------------|
| **Magic (4 bytes)**          | 4 bytes |It always contains “STEG” to identify steganographic data.            |
| Version (1 byte)**           | 1 byte  |Version of the format, currently 1.                                   | 
| **Total Length (8 bytes)**   | 8 bytes | Size of the encrypted/encrypted message in bytes.                    |
| **Current Offset (8 bytes)** | 8 bytes | Position within multipart messages (if the message is split into several images). |
| **Message Hash (8 bytes)**   | 8 bytes | First 8 bytes of the SHA-256 hash of the original message to verify its integrity. |
| Message ID (4 bytes)**       | 4 bytes | 32-bit random identifier used for message retrieval.                 |
| **Reserved (3 bytes)**       | 3 bytes | Unused space for future extensions.                                  | 

## 🛠️ **Header Implementation**

The `StegoHeader` structure provides two main methods for handling the header:

### Methods

* **`to_bytes()`**: Serializes the header into an array of 36 bytes. This method converts the structure into a binary format that can be easily inserted into the image or transmitted.
* **`from_bytes()`**: Takes an array of bytes and parses it to reconstruct the header structure, ensuring that the data is valid and consistent with the expected format.

# 🔐 Module `crypto.rs`.

Implementation of basic cryptographic operations for secure encryption and hashing.

## 📋 Summary of Functions

| Field    | Description   |
|----------|---------------|
| **hash_message** |  📊 Generates a truncated SHA-256 hash             |
| **encrypt_message**     | 🔒 Data encryption with AES-256-GCM              |
| **decrypt_message** |    🔓 Decrypts data encrypted with AES-256-GCM           | 

# 📁 MessageIndexDB

SQLite database for indexing hidden messages in images.

## 🛠️ Main methods

| Método | Descripción |
| --- | --- |
| `new()` | 🆕 Creates or connects to the database  |
| `register()` | 📝 Saves a new message in the index |
| `get_message_location()` | 🔍 Finds a message by its message ID|
| `get_all_messages()` | 📋 Lists all registered messages |

## 💾 Stored data

The database manages essential information about each steganographic message, including its unique identifier, the path to the image file containing it, the exact position in bytes where the message begins within the file, and a hash to verify the integrity of the content.