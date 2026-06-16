# IronKeys

IronKeys is a personal Android keyboard project focused on private, compact
communication from the keyboard itself.

It keeps the lightweight, no-ads, open-source keyboard experience inherited from
[Unexpected Keyboard](https://github.com/Julow/Unexpected-Keyboard), and builds a
new identity around local key management, public-key exchange, and short
encrypted messages.

## What IronKeys Is About

- A privacy-conscious Android virtual keyboard.
- Corner-swipe keys for symbols and extra characters, inherited from Unexpected
  Keyboard.
- Layouts that stay practical for Termux, programming, and everyday writing.
- Local IronKeys private identities backed by Android storage.
- Public-key sharing by text, backup files, and QR scanning.
- Short message encryption and decryption from the keyboard workflow.
- Hybrid key material using P-256 and ML-KEM-768, with AES-GCM for encrypted
  payloads.

IronKeys is not meant to erase its origin. Unexpected Keyboard is the base that
made this project possible: the keyboard engine, layout model, translation work,
documentation, and a large part of the user-facing behavior come from that
project. The goal here is to keep that foundation visible while growing a more
personal direction on top of it.

## Keyboard interaction

The core typing model is still the Unexpected Keyboard model: each key can expose
extra symbols in its corners, and swiping toward a corner types that symbol.

For example, if a key shows a symbol in the lower-left corner, swipe the key
toward the lower-left direction to type it. This keeps common letters easy to
tap while making programming symbols, punctuation, modifiers, and utility keys
available without opening several symbol panes.

| <img src="/fastlane/metadata/android/en-US/images/phoneScreenshots/1.png" alt="Screenshot-1" /> | <img src="/fastlane/metadata/android/en-US/images/phoneScreenshots/2.png" alt="Screenshot-2"/> | <img src="/fastlane/metadata/android/en-US/images/phoneScreenshots/3.png" alt="Screenshot-3"/> |
| --- | --- | --- |
| <img src="/fastlane/metadata/android/en-US/images/phoneScreenshots/4.png" alt="Screenshot-4" /> | <img src="/fastlane/metadata/android/en-US/images/phoneScreenshots/5.png" alt="Screenshot-5" /> | <img src="/fastlane/metadata/android/en-US/images/phoneScreenshots/6.png" alt="Screenshot-6" /> |

## IronKeys features

IronKeys adds a small encrypted-message layer to the keyboard:

- Generate private identities on the device.
- Import and export private-key backups.
- Share public keys as text blocks or QR codes.
- Scan and store other people's public keys.
- Encrypt short messages for a selected recipient.
- Decrypt IronKeys messages with a matching private key.

Private-key storage requires Android 6.0 or newer because it depends on Android
Keystore support.

## Project roots

IronKeys is derived from
[Unexpected Keyboard](https://github.com/Julow/Unexpected-Keyboard), a
lightweight and privacy-conscious Android keyboard originally designed for
programmers using Termux and now useful for general typing.

This repository keeps that lineage explicit. When upstream documentation,
translations, layouts, or technical decisions still refer to Unexpected
Keyboard, treat them as inherited context unless a later IronKeys-specific note
replaces them.

## Contributing

This branch is currently about shaping the IronKeys identity without losing the
Unexpected Keyboard foundation.

See [CONTRIBUTING.md](CONTRIBUTING.md) for build instructions and general
development notes.

### Base keyboard

For changes to the base keyboard experience, layouts, generic typing behavior,
translations, or shared documentation, I prefer contributions to go to the
original [Unexpected Keyboard](https://github.com/Julow/Unexpected-Keyboard)
project.

I will keep this repository updated from upstream so those improvements can flow
back into IronKeys without fragmenting the original project.

### IronKeys-specific changes

Changes related to the IronKeys direction belong here. That includes encryption,
key management, public-key sharing, QR flows, encrypted-message UX, and the
identity work needed to make this repository feel like IronKeys while preserving
its roots.

## License

This project is distributed under the GNU General Public License v3. See
[LICENSE](LICENSE).

## Acknowledgements

- [Unexpected Keyboard](https://github.com/Julow/Unexpected-Keyboard) and its
  contributors for the original keyboard project.
- The [NLnet foundation](https://nlnet.nl/) for funding work on the
  spell-checking feature inherited from Unexpected Keyboard.
