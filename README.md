# Touchie

Touchie is a small binary written in Swift that allows scripts to access the Mac Keychain guarded by TouchID.

Macs come with the `security` command which can get and set secrets to the Keychain:

```bash
# Save a key/value to the default "login" keychain, with key "MyKeyName", update if exists (-U), 
# allow no app to access without a prompt (-T ""), and prompt for secret to store (-w)
security add-generic-password -a login -s "MyKeyName" -T "" -U -w

# Get the secret value from a key
security find-generic-password -s "MyKeyName" -w
```

You can use `security` in a script, but (AFAIK) you can't tell it to use biometrics to guard secrets, you have to enter the password each time, or "always allow" the `security` binary to access the secret.

🔑 Touchie fixes this.

## Installation

### Using Homebrew (Recommended)

1.  Tap the custom Homebrew tap (you only need to do this once)
    ```bash
    brew tap reubenmiller/homebrew-touchie
    ```

2.  Install Touchie:
    ```bash
    brew install touchie
    ```

### Manual Build

Compile the `touchie.swift` into a binary:

```bash
swiftc touchie.swift -o touchie
```

Put the binary somewhere in your path.

## Save a secret to the keychain

`touchie set MyKeyName MySecret`

## Retrieve a secret

`touchie get MyKeyName`

The first time you `get` the secret, you should "always allow" the `touchie` binary. Upon subsequent accesses, you will always be prompted for TouchID in order to access the secret.

To change the secret, you can use the `Keychain Access.app` that comes with your Mac.

You can use `touchie` in bash scripts or Automator Workflows, or wherever you need secure access to a secret.
