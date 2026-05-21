# mini-shai-hulud

Sjekker om lockfiles er påvirket av Mini Shai-Hulud

## Usage

Kjør [pc-checker](./pc-checker.py)-scriptet. Der er det konfigurert hvilken
mappe som blir sjekket. Som standard er det hele hjemmeområdet.

`$ python pc-checker.py`

### Med spesifisert mappe

Du kan også spesifisere rot-mappe for scanningen ved å legge ved et argument.

`$ python pc-checker.py ../min-kode`

## Støttede formater

- `package-lock.json` (npm)
- `yarn.lock` (Yarn v1)
- `pnpm-lock.yaml` (pnpm) — krever PyYAML: `$ pip install pyyaml`

Uten PyYAML vil `pnpm`-repoer bli hoppet over, mens npm og Yarn fungerer som normalt.
