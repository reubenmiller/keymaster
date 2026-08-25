# Touchie

Touchie is a small binary written in Swift that allows scripts to access the Mac Keychain guarded by TouchID.

Touchie only lists the secrets created by touchie, so you don't have to worry it accessing things it shouldn't.

**Note:** Based on the [johnthethird/keymaster](https://github.com/johnthethird/keymaster) project, and extended with the help of AI.

## Features

Common examples showing off what touchie can do:

The first time you `get` the secret, you should "always allow" the `touchie` binary. Upon subsequent accesses, you will always be prompted for TouchID in order to access the secret.

```sh
# set a secret, you'll be prompted for the secret value
touchie set mysecret

# set a secret only if it does not exist already
touchie set mysecret --no-clobber

# Get a secret
touchie get mysecret

# Get a secret by a regex (must only match one value)
touchie get --regex mysecret

# List secrets (but don't show the passwords)
touchie list

# List secrets which match a regex filter
touchie list '^C8Y'

# Delete a secret
touchie delete mysecret
```

## Installation

### Using Homebrew (Recommended)

```bash
brew trust reubenmiller/iot-tap
brew install reubenmiller/iot-tap/touchie
```

**Note** The Formula and bottles are currently hosted in [reubenmiller/homebrew-iot-tap](https://github.com/reubenmiller/homebrew-iot-tap)

### Manual Build

Compile the `touchie.swift` into a binary:

```bash
swiftc touchie.swift -o touchie
```

Put the binary somewhere in your path.

## Get help

```sh
touchie --help
```

Get the full list of supported commands and list of all options.

## go-c8y-cli users

If you want to use touchie to store your [go-c8y-cli](https://goc8ycli.netlify.app/) session encryption passphrase, then you can add the following to your shell profile.


**file: ~/.zshrc**

```sh
eval "$(c8y settings update pinEntry "touchie get" --shell auto)"

# or just explicitly setting the env variable
export C8Y_SETTINGS_PINENTRY="touchie get"
```

Then reload your zsh.

Now set your [go-c8y-cli](https://goc8ycli.netlify.app/) session passphrase in keychain using the following command:

```sh
touchie set C8Y_PASSPHRASE
```

Now, you can activate sessions, and then you'll be prompted for your TouchID credentials when switching a session.

```sh
set-session
```

**Note:** You will be prompted for your password the first time, and as long as you select the "Always allow" then you shouldn't be prompted again.
