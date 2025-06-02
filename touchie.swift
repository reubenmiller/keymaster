// Touchie, access Keychain secrets guarded by TouchID
//
import Darwin // For getpass()
import Foundation
import LocalAuthentication

// Policy for Touch ID/Face ID authentication
let policy = LAPolicy.deviceOwnerAuthenticationWithBiometrics
// Unique label to identify keychain entries managed by this touchie tool
let touchieLabelValue = "com.github.reubenmiller.touchie.entry"

// Helper to print to stderr
func printErr(_ message: String) {
    fputs(message + "\n", stderr)
}

// Helper to print to stderr without a newline
func printErrNoNL(_ message: String) {
    fputs(message, stderr)
}

func setPassword(key: String, password: String, addOnly: Bool) -> Bool {
  // Data for the keychain item
  let valueData = password.data(using: .utf8)!

  // Query to find an existing item managed by touchie
  let queryForUpdate: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: key,
    kSecAttrLabel as String: touchieLabelValue // Ensure we only target touchie entries
  ]

  if addOnly {
    // --no-clobber / addOnly mode: only add if it doesn't exist
    var item: CFTypeRef?
    let existingStatus = SecItemCopyMatching(queryForUpdate as CFDictionary, &item)

    if existingStatus == errSecSuccess {
      // Item already exists, and we are in addOnly mode
      printErr("Key '\(key)' already exists in keychain. Not overwriting due to --no-clobber flag.")
      return false // Indicate failure to add because it exists and addOnly is true
    } else if existingStatus == errSecItemNotFound {
      // Item does not exist, proceed to add (after checking for unlabeled)
      // Check if an item with the same service key exists *without* our label.
      let queryForUnlabeledExisting: [String: Any] = [
          kSecClass as String: kSecClassGenericPassword,
          kSecAttrService as String: key
      ]
      var unlabeledItem: CFTypeRef?
      let unlabeledCheckStatus = SecItemCopyMatching(queryForUnlabeledExisting as CFDictionary, &unlabeledItem)

      if unlabeledCheckStatus == errSecSuccess {
        printErr("Error: An item with key '\(key)' already exists but is not managed by touchie (it lacks the touchie label).")
        printErr("To manage this item with touchie, it must first be removed or updated to include the touchie label by other means.")
        return false
      } else if unlabeledCheckStatus == errSecItemNotFound {
        // Good, no conflicting unlabeled item. Proceed to add a new, labeled item.
        let attributesForAdd: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: key,
            kSecAttrLabel as String: touchieLabelValue, // Add the touchie label
            kSecValueData as String: valueData
        ]
        let addStatus = SecItemAdd(attributesForAdd as CFDictionary, nil)
        if addStatus == errSecDuplicateItem {
            printErr("Error: Failed to add password for key '\(key)'. A duplicate item might exist despite checks. Status: \(addStatus)")
            return false
        }
        return addStatus == errSecSuccess
      } else {
        printErr("Error checking for existing unlabeled item for key '\(key)'. Status: \(unlabeledCheckStatus)")
        return false
      }
    } else {
      // Some other error occurred while checking for existing touchie item
      printErr("Error checking for existing touchie-managed item for key '\(key)'. Status: \(existingStatus)")
      return false
    }
  } else {
    // Default mode: update if exists, otherwise add
    let attributesToUpdate: [String: Any] = [
      kSecValueData as String: valueData
    ]
    var status = SecItemUpdate(queryForUpdate as CFDictionary, attributesToUpdate as CFDictionary)

    if status == errSecItemNotFound {
      // No item found with our key AND label by SecItemUpdate.
      // Check if an item with the same service key exists *without* our label.
      let queryForUnlabeledExisting: [String: Any] = [
          kSecClass as String: kSecClassGenericPassword,
          kSecAttrService as String: key
      ]
      var unlabeledItem: CFTypeRef?
      let unlabeledCheckStatus = SecItemCopyMatching(queryForUnlabeledExisting as CFDictionary, &unlabeledItem)

      if unlabeledCheckStatus == errSecSuccess {
          printErr("Error: An item with key '\(key)' already exists but is not managed by touchie (it lacks the touchie label).")
          printErr("To manage this item with touchie, it must first be removed or updated to include the touchie label by other means.")
          return false
      } else if unlabeledCheckStatus == errSecItemNotFound {
          let attributesForAdd: [String: Any] = [
              kSecClass as String: kSecClassGenericPassword,
              kSecAttrService as String: key,
              kSecAttrLabel as String: touchieLabelValue,
              kSecValueData as String: valueData
          ]
          status = SecItemAdd(attributesForAdd as CFDictionary, nil)
          if status == errSecDuplicateItem {
              printErr("Error: Failed to add password for key '\(key)'. A duplicate item might exist despite checks. Status: \(status)")
              return false
          }
      } else {
          printErr("Error checking for existing unlabeled item for key '\(key)'. Status: \(unlabeledCheckStatus)")
          return false
      }
    } else if status != errSecSuccess {
      printErr("Error updating password for key '\(key)'. Status: \(status)")
      return false
    }
    return status == errSecSuccess
  }
}

func deletePassword(key: String) -> OSStatus {
  let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: key,
    kSecAttrLabel as String: touchieLabelValue // Ensure we only delete touchie entries
  ]
  let status = SecItemDelete(query as CFDictionary)
  return status
}

// Checks if an exact key exists and is managed by touchie.
// This function does NOT require biometric authentication.
// It prints errors to stderr if the key is not found or an error occurs.
func checkExactKeyExists(key: String) -> Bool {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: key,
        kSecAttrLabel as String: touchieLabelValue
        // kSecMatchLimit is implicitly kSecMatchLimitOne if not kSecMatchLimitAll
    ]
    var junkItemResult: CFTypeRef? // Required for SecItemCopyMatching, but we only care about status
    let status = SecItemCopyMatching(query as CFDictionary, &junkItemResult)

    if status == errSecSuccess {
        return true // Item exists
    } else if status == errSecItemNotFound {
        printErr("Error: Password for key '\(key)' not found or not managed by touchie.")
        return false // Item does not exist
    } else {
        printErr("Error checking for key '\(key)' in keychain. Status: \(status). (\(SecCopyErrorMessageString(status, nil) as String? ?? "Unknown OSStatus"))")
        return false
    }
}

// Attempts to find a unique key name matching the regex pattern.
// This function does NOT require biometric authentication.
// It prints errors to stderr if no unique match is found.
func resolveKeyFromPattern(pattern: String) -> String? {
  // 1. Query all touchie-managed items to get their service attributes
  let queryAllItems: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrLabel as String: touchieLabelValue,
    kSecMatchLimit as String: kSecMatchLimitAll,
    kSecReturnAttributes as String: true // We need kSecAttrService
  ]
  var cfArrayResult: CFTypeRef?
  let listStatus = SecItemCopyMatching(queryAllItems as CFDictionary, &cfArrayResult)

  guard listStatus == errSecSuccess else {
    if listStatus == errSecItemNotFound {
      printErr("No touchie-managed passwords found in keychain to match against pattern '\(pattern)'.")
    } else {
      printErr("Error fetching keys from keychain to match against pattern. Status: \(listStatus)")
    }
    return nil
  }
  guard let retrievedItems = cfArrayResult as? [[String: Any]] else {
    printErr("Error: Unexpected data format received from keychain when listing for regex match.")
    return nil
  }
  if retrievedItems.isEmpty {
    printErr("No touchie-managed passwords found in keychain to match against pattern '\(pattern)'.")
    return nil
  }

  // 2. Compile the regex
  let regex: NSRegularExpression
  do {
    regex = try NSRegularExpression(pattern: pattern, options: [])
  } catch {
    printErr("Error: Invalid regular expression provided for get: \(error.localizedDescription)")
    return nil
  }

  // 3. Filter items by regex on service name
  var matchedServiceNames: [String] = []
  for item in retrievedItems {
    if let serviceName = item[kSecAttrService as String] as? String {
      let range = NSRange(location: 0, length: serviceName.utf16.count)
      if regex.firstMatch(in: serviceName, options: [], range: range) != nil {
        matchedServiceNames.append(serviceName)
      }
    }
  }

  // 4. Check match count
  if matchedServiceNames.isEmpty {
    printErr("No key found matching regex pattern: '\(pattern)'")
    return nil
  } else if matchedServiceNames.count > 1 {
    let sortedMatches = matchedServiceNames.sorted().joined(separator: ", ")
    printErr("Multiple keys found matching regex pattern '\(pattern)': \(sortedMatches). Please be more specific or use an exact key name.")
    return nil
  } else {
    // Exactly one match
    return matchedServiceNames[0]
  }
}

// Fetches the password for a given exact key name.
// This function should be called after successful biometric authentication.
func fetchPasswordForExactKey(key: String) -> String? {
  let queryPassword: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: key,
    kSecAttrLabel as String: touchieLabelValue,
    kSecMatchLimit as String: kSecMatchLimitOne,
    kSecReturnData as String: true
  ]
  var itemDataResult: CFTypeRef?
  let fetchStatus = SecItemCopyMatching(queryPassword as CFDictionary, &itemDataResult)
  guard fetchStatus == errSecSuccess,
        let passwordData = itemDataResult as? Data,
        let password = String(data: passwordData, encoding: .utf8)
  else {
    if fetchStatus == errSecItemNotFound {
         printErr("Error: Password for key '\(key)' not found or not managed by touchie.")
    } else {
         printErr("Error retrieving password for key '\(key)'. Status: \(fetchStatus). (\(SecCopyErrorMessageString(fetchStatus, nil) as String? ?? "Unknown OSStatus"))")
    }
    return nil
  }

  return password
}

func listPasswords(regexPattern: String? = nil) -> Bool {
  let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrLabel as String: touchieLabelValue, // Filter by the touchie label
    kSecMatchLimit as String: kSecMatchLimitAll,
    kSecReturnAttributes as String: true,
    // kSecAttrSynchronizable as String: kSecAttrSynchronizableAny // Optional: uncomment to include iCloud keychain items
  ]

  var cfArrayResult: CFTypeRef?
  let status = SecItemCopyMatching(query as CFDictionary, &cfArrayResult)

  if status == errSecItemNotFound {
    printErr("No touchie-managed passwords found in keychain.")
    return false // No items to list, so operation did not produce list output
  }

  guard status == errSecSuccess else {
    // For more detailed error, you could use:
    // let errorDescription = SecCopyErrorMessageString(status, nil) as String? ?? "Unknown OSStatus"
    // printErr("Error fetching passwords from keychain. Status: \(status) (\(errorDescription))")
    printErr("Error fetching touchie-managed passwords from keychain. Status: \(status)")
    return false // Operation failed
  }

  guard let retrievedItems = cfArrayResult as? [[String: Any]] else {
    // This should not happen if status is errSecSuccess with kSecMatchLimitAll
    fputs("Error: Unexpected data format received from keychain.\n", stderr)
    return false
  }

  if retrievedItems.isEmpty {
    printErr("No touchie-managed passwords found in keychain.")
    return false // No items to list
  }

  var regex: NSRegularExpression?
  if let pattern = regexPattern, !pattern.isEmpty {
    do {
      regex = try NSRegularExpression(pattern: pattern, options: [])
    } catch {
      printErr("Error: Invalid regular expression provided: \(error.localizedDescription)")
      return false
    }
  }

  var servicesToPrint: [String] = []
  for item in retrievedItems {
    if let service = item[kSecAttrService as String] as? String {
      if let regex = regex {
        let range = NSRange(location: 0, length: service.utf16.count)
        if regex.firstMatch(in: service, options: [], range: range) != nil {
          servicesToPrint.append(service)
        }
      } else {
        servicesToPrint.append(service)
      }
    }
  }

  if servicesToPrint.isEmpty {
    // If retrievedItems was not empty but servicesToPrint is,
    // it means either the regex matched nothing, or items lacked the service attribute.
    if regexPattern != nil {
      // This message is specific to a filter yielding no results.
      printErr("No keys found matching the regex pattern: '\(regexPattern!)'")
    }
    // If no regex and servicesToPrint is empty, the earlier checks for empty retrievedItems
    // would have printed "No touchie-managed passwords found...".
    return false // No items were ultimately listed
  }

  fputs("Stored touchie-managed keys (services):\n", stderr) // Header to stderr
  for service in servicesToPrint {
    print("- \(service)") // Actual keys to stdout
  }
  return true // Items were listed
}

func usage() {
  let programName = "touchie"
  print("""
  Usage: \(programName) <command> [options]

  A simple command-line tool to manage passwords in the macOS Keychain,
  secured by Touch ID or Face ID.

  Commands:
    get <key>                     Retrieve and print the password for exact <key>.
    get --regex <pattern>         Retrieve password if <pattern> uniquely matches one key.
    set <key> [<password>]        Set the password for <key>.
                                  If <password> is not provided, you will be prompted.
    delete <key>                  Delete the password for <key> from the keychain.
    list [<regex_filter>]         List keys managed by \(programName), optionally filtered by <regex_filter>.
    help, --help, -h              Show this help message.

  Options for 'set' command:
    --no-clobber                  Only set the password if <key> does not already exist.

  Examples:
    \(programName) set myServiceAPIKey                            # Set password for 'myServiceAPIKey', will prompt for password
    \(programName) set myServiceAPIKey S3cr3tP@sswOrd             # Set password for 'myServiceAPIKey' directly
    \(programName) set newAppKey --no-clobber                    # Set password for 'newAppKey' only if it doesn't exist, will prompt
    \(programName) set newAppKey S3cr3t --no-clobber             # Set password for 'newAppKey' directly, only if it doesn't exist    
    \(programName) get myServiceAPIKey                            # Retrieve password for 'myServiceAPIKey'
    \(programName) get --regex "^myService.*Key$"                 # Retrieve password if regex uniquely matches
    \(programName) list                                          # List all stored keys
    \(programName) delete myServiceAPIKey                        # Delete password for 'myServiceAPIKey'
    \(programName) --help                                       # Show this help message

  """)
}

func main() {
  let inputArgs: [String] = Array(CommandLine.arguments.dropFirst())

  // Check for help flags
  if inputArgs.contains("--help") || inputArgs.contains("-h") {
    usage()
    exit(EXIT_SUCCESS)
  }

  if inputArgs.isEmpty {
    printErr("Error: No action specified.")
    usage()
    exit(EXIT_FAILURE)
  }

  let action = inputArgs[0]

  // Handle 'list' action separately as it doesn't require Touch ID
  if action == "list" {
    if inputArgs.count > 2 { // Allows 'list' or 'list <regex>'
      printErr("Error: 'list' action takes at most one optional regex filter argument.")
      usage()
      exit(EXIT_FAILURE)
    }
    
    let regexFilter = inputArgs.count == 2 ? inputArgs[1] : nil
    if listPasswords(regexPattern: regexFilter) {
        exit(EXIT_SUCCESS)
    } else {
      // listPasswords() already prints specific error messages
      exit(EXIT_FAILURE)
    }
  }

  // For actions requiring Touch ID (set, get, delete)
  let context = LAContext()
  context.touchIDAuthenticationAllowableReuseDuration = 0 // Require fresh authentication each time

  var authPolicyError: NSError?
  guard context.canEvaluatePolicy(policy, error: &authPolicyError) else {
    let errorMsg = authPolicyError?.localizedDescription ?? "Policy not satisfiable"
    printErr("This Mac doesn't support deviceOwnerAuthenticationWithBiometrics or it's not configured. Error: \(errorMsg)")
    exit(EXIT_FAILURE)
  }

  switch action {
  case "set":
    var key: String
    var secret: String
    var noClobber = false
    
    // Process arguments for 'set' command
    var remainingArgs = inputArgs.dropFirst() // Arguments after "set"

    if remainingArgs.isEmpty {
        printErr("Error: 'set' action requires a key.")
        usage()
        exit(EXIT_FAILURE)
    }
    key = String(remainingArgs.removeFirst()) // Extract the key

    // Check for --no-clobber flag
    if let noClobberIndex = remainingArgs.firstIndex(of: "--no-clobber") {
        noClobber = true
        remainingArgs.remove(at: noClobberIndex)
    }

    // Determine secret (either from remaining arg or prompt)
    if remainingArgs.count == 1 {
        secret = String(remainingArgs.first!)
    } else if remainingArgs.isEmpty {
      // No password provided on CLI, prompt if necessary
      if noClobber {
        // With --no-clobber, check if item exists before prompting
        let queryForKeyExistence: [String: Any] = [
          kSecClass as String: kSecClassGenericPassword,
          kSecAttrService as String: key,
          kSecAttrLabel as String: touchieLabelValue
        ]
        var item: CFTypeRef?
        let existingStatus = SecItemCopyMatching(queryForKeyExistence as CFDictionary, &item)

        if existingStatus == errSecSuccess {
          printErr("Key '\(key)' already exists in keychain. Not prompting for password due to --no-clobber flag.")
          exit(EXIT_FAILURE) // Or EXIT_SUCCESS if preferred for "no action taken as requested"
        } else if existingStatus != errSecItemNotFound {
          // An error occurred other than item not found
          let errorDescription = SecCopyErrorMessageString(existingStatus, nil) as String? ?? "Unknown OSStatus"
          printErr("Error checking keychain for key '\(key)' before prompting: \(existingStatus) (\(errorDescription)).")
          exit(EXIT_FAILURE)
        }
        // If errSecItemNotFound, proceed to prompt below
      }

      printErrNoNL("Enter password for key '\(key)' [input is hidden]: ")
      fflush(stderr) // Ensure prompt is shown before getpass
      if let cPassword = getpass("") {
        let enteredPassword = String(cString: cPassword)
        if enteredPassword.isEmpty {
          printErr("Password input was empty. Operation cancelled, no password will be set.")
          exit(EXIT_FAILURE)
        }
        secret = enteredPassword
      } else {
        printErr("Password input cancelled or failed. No password will be set.")
        exit(EXIT_FAILURE)
      }
    } else {
        // Too many arguments after processing key and flag
        printErr("Error: Invalid arguments for 'set' action.")
        printErr("See usage for correct format.")
        usage()
            exit(EXIT_FAILURE)
        }
    context.evaluatePolicy(policy, localizedReason: "set the password for \(key)") { success, authError in
      if success && authError == nil {
        if setPassword(key: key, password: secret, addOnly: noClobber) {
            printErr("Key '\(key)' has been successfully set in the keychain.")
            exit(EXIT_SUCCESS)
        } else {
          // setPassword function already prints specific error or "already exists" message
          exit(EXIT_FAILURE)
        }
      } else {
        let errorDescription = authError?.localizedDescription ?? "Unknown error"
        printErr("Authentication failed or was canceled: \(errorDescription)")
        exit(EXIT_FAILURE)
      }
    }
    dispatchMain()

  case "get":
    var keyOrPatternArg: String
    var useRegex = false

    if inputArgs.count == 2 { // e.g., "touchie get mykey"
        keyOrPatternArg = inputArgs[1]
        useRegex = false
    } else if inputArgs.count == 3 && inputArgs[1] == "--regex" { // e.g., "touchie get --regex mypattern"
        keyOrPatternArg = inputArgs[2]
        useRegex = true
    } else {
        printErr("Error: Invalid arguments for 'get' action.")
        printErr("Usage: touchie get <key>")
        printErr("   or: touchie get --regex <pattern>")
        exit(EXIT_FAILURE)
    }

    let finalKeyName: String // Will hold the key name to use for auth and fetching

    if useRegex {
        guard let resolvedKey = resolveKeyFromPattern(pattern: keyOrPatternArg) else {
            // resolveKeyFromPattern already printed the error (no match, multiple matches, etc.)
            // No need to prompt for auth if we don't have a unique key.
            exit(EXIT_FAILURE) 
        }
        finalKeyName = resolvedKey
    } else { // Exact key name
        // Pre-check for existence BEFORE Touch ID prompt
        if !checkExactKeyExists(key: keyOrPatternArg) {
            // checkExactKeyExists already printed the error message
            exit(EXIT_FAILURE)
        }
        finalKeyName = keyOrPatternArg
    }
    
    let reason = "access the password for key '\(finalKeyName)'"
    context.evaluatePolicy(policy, localizedReason: reason) { success, authError in
      if success && authError == nil {
        guard let password = fetchPasswordForExactKey(key: finalKeyName) else {
          // fetchPasswordForExactKey prints its own errors (e.g., "key not found")
          exit(EXIT_FAILURE)
        }
        print(password)
        exit(EXIT_SUCCESS)
      } else {
        printErr("Authentication failed or was canceled: \(authError?.localizedDescription ?? "Unknown error")")
        exit(EXIT_FAILURE)
      }
    }
    dispatchMain()

  case "delete":
    if inputArgs.count != 2 {
      printErr("Error: 'delete' action requires a key.")
      usage()
      exit(EXIT_FAILURE)
    }
    let key = inputArgs[1]
    context.evaluatePolicy(policy, localizedReason: "delete the password for \(key)") { success, authError in
      if success && authError == nil {
        let deleteStatus = deletePassword(key: key)
        switch deleteStatus {
        case errSecSuccess:
          printErr("Key '\(key)' has been successfully deleted from the keychain.")
          exit(EXIT_SUCCESS)
        case errSecItemNotFound: // This case should ideally be caught by a pre-check if we add one for delete
          printErr("Error: Password for key '\(key)' not found or not managed by touchie.")
          exit(EXIT_FAILURE)
        default:
          let errorDescription = SecCopyErrorMessageString(deleteStatus, nil) as String? ?? "Unknown OSStatus"
          printErr("Error deleting password for key '\(key)'. Status: \(deleteStatus) (\(errorDescription)).")
          exit(EXIT_FAILURE)
        }
      } else {
        printErr("Authentication failed or was canceled: \(authError?.localizedDescription ?? "Unknown authentication error")")
        exit(EXIT_FAILURE)
      }
    }
    dispatchMain()

  default:
    printErr("Error: Unknown action '\(action)'.")
    usage()
    exit(EXIT_FAILURE)
  }
}
main()