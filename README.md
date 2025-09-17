# shaihu

A simple CLI tool to check if an npm project is depending on known vulnerable packages.

Created because of the [Shai-Hulud supply chain attack](https://www.ox.security/blog/npm-2-0-hack-40-npm-packages-hit-in-major-supply-chain-attack/) and named after [Shai Hu](https://www.wowhead.com/mop-classic/npc=61069/shai-hu), an NPC in WoW - Mists of Pandaria

## Installation

```bash
go install github.com/filipekiss/shaihu@latest
```

You also need a list of packages to check against. You can find it in the [compromised-packages.txt](compromised-packages.txt) file or you can provide your own.

## Usage

```bash
shaihu <path-to-compromised-packages.txt> <folder-to-check>
```

Example:

```bash
shaihu compromised-packages.txt .
```

`shaihu` will recursively search for `package.json` files in the given folder and check if they are depending on any of the compromised packages.

If any of the compromised packages is found, it will print the path to the `package.json` file and the version of the package.  

By default it ignores `node_modules` folders, but you can pass the `--node-modules` flag to include them.

Example:

```bash
shaihu --node-modules compromised-packages.txt .
```

## License

MIT
