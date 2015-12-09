# ghsshare

Share short secrets using GitHub's SSH keys

## Usage

On encrypt mode it encrypts the standard input using the SSH key stored on
GitHub for `username`. Otherwise, it decrypts the input using the specified
private key.

```
usage: ghsshare [flags] [username]
  -decrypt
    	Decrypt the input instead of encrypting
  -github-api-endpoint string
    	GitHub's API endpoint (for using with enterprise setups (default "https://api.github.com")
  -private-key string
    	The private key file used to decrypt (default "~/.ssh/id_rsa")
```

You can do something like:

```
$ echo "secret" | ghsshare amanya | ghsshare --decrypt
```

## Limits

The RSA cryptosystem is designed for passing encrypted shared keys so it has
limited the amount of data that can encrypt to ~200 bytes.
