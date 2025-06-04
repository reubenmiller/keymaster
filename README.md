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

If you want to use touchie to store your [go-c8y-cli](https://goc8ycli.netlify.app/) session encryption passphrase, then you can add a modified `set-session` shell function to your zshrc profile, though it should be placed after the `c8y cli profile`, or after the loading of the oh-my-zsh.

**file: ~/.zshrc**

```sh
set-session() {
    if command -V touchie >/dev/null 2>&1; then
      c8yenv=$(C8Y_PASSPHRASE="$(touchie get C8Y_PASSPHRASE)" c8y sessions set --noColor=false $@ )
    else
      c8yenv=$(c8y sessions set --noColor=false $@ )
    fi
    
    code=$?
    if [ $code -ne 0 ]
    then
      echo "Set session failed"
      return 1
    fi
    eval "$c8yenv"
}
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
