# FrozenCryptor

FrozenCryptor is a file encryption utility which can prep itself and drop a note if required.

## Usage

```
mfe.exe <run/clean/prep> -t <target_folder> [-e <extension>] [-r <true/false>]
	-t : Folder to use
	-e : Extension to use (optional argument)
	-r : Leave a note (optional argument)
```

## Prepare Directory

Simple utility to prepare a target folder for encryption activity by generating a nested directory structure with files for encryption.

## Usage

```
prepare_directory.exe -t {{target_folder}}
```

# Building

To build:

```
cargo build --release
```

To cross-compile for Windows from a Linux machine:

```
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu
```

# Credits

Developed by [Jason Kelly](https://github.com/kellyjason21) for Security Risk Advisors (sra.io)

