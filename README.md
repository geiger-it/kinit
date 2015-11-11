# kinit
Validate credentials using the Kerberos `kinit` executable. For PHP.

**Warning!** This script relies on the internal implementation of the `kinit` executable and as such should be used with extreme care (use at your own risk).

## Installation
### Via Command Line
```sh
$ composer config repositories.dirish/kinit vcs https://github.com/dirish/kinit.git
```
```sh
$ composer require dirish/kinit dev-master
```
### Via composer.json
```json
    "require": {
        "dirish/kinit": "dev-master"
    },
    "repositories": {
        "dirish/kinit": {
            "type": "vcs",
            "url": "https://github.com/dirish/kinit.git"
        }
    }
```