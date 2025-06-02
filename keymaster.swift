// Keymaster, access Keychain secrets guarded by TouchID
//
import Darwin // For getpass()
import Foundation
import LocalAuthentication

// Policy for Touch ID/Face ID authentication
let policy = LAPolicy.deviceOwnerAuthenticationWithBiometrics
// Unique label to identify keychain entries managed by this keymaster tool
let keymasterLabelValue = "com.github.reubenmiller.keymaster.entry"

func setPassword(key: String, password: String, addOnly: Bool) -> Bool {
  // Data for the keychain item
  let valueData = password.data(using: .utf8)!

  // Query to find an existing item managed by keymaster
  let queryForUpdate: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: key,
    kSecAttrLabel as String: keymasterLabelValue // Ensure we only target keymaster entries
  ]

  if addOnly {
    // --no-clobber / addOnly mode: only add if it doesn't exist
    var item: CFTypeRef?
    let existingStatus = SecItemCopyMatching(queryForUpdate as CFDictionary, &item)

    if existingStatus == errSecSuccess {
      // Item already exists, and we are in addOnly mode
      print("Key '\(key)' already exists in keychain. Not overwriting due to --no-clobber flag.")
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
        print("Error: An item with key '\(key)' already exists but is not managed by keymaster (it lacks the keymaster label).")
        print("To manage this item with keymaster, it must first be removed or updated to include the keymaster label by other means.")
        return false
      } else if unlabeledCheckStatus == errSecItemNotFound {
        // Good, no conflicting unlabeled item. Proceed to add a new, labeled item.
        let attributesForAdd: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: key,
            kSecAttrLabel as String: keymasterLabelValue, // Add the keymaster label
            kSecValueData as String: valueData
        ]
        let addStatus = SecItemAdd(attributesForAdd as CFDictionary, nil)
        if addStatus == errSecDuplicateItem {
            print("Error: Failed to add password for key '\(key)'. A duplicate item might exist despite checks. Status: \(addStatus)")
            return false
        }
        return addStatus == errSecSuccess
      } else {
        print("Error checking for existing unlabeled item for key '\(key)'. Status: \(unlabeledCheckStatus)")
        return false
      }
    } else {
      // Some other error occurred while checking for existing keymaster item
      print("Error checking for existing keymaster-managed item for key '\(key)'. Status: \(existingStatus)")
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
          print("Error: An item with key '\(key)' already exists but is not managed by keymaster (it lacks the keymaster label).")
          print("To manage this item with keymaster, it must first be removed or updated to include the keymaster label by other means.")
          return false
      } else if unlabeledCheckStatus == errSecItemNotFound {
          let attributesForAdd: [String: Any] = [
              kSecClass as String: kSecClassGenericPassword,
              kSecAttrService as String: key,
              kSecAttrLabel as String: keymasterLabelValue,
              kSecValueData as String: valueData
          ]
          status = SecItemAdd(attributesForAdd as CFDictionary, nil)
          if status == errSecDuplicateItem {
              print("Error: Failed to add password for key '\(key)'. A duplicate item might exist despite checks. Status: \(status)")
              return false
          }
      } else {
          print("Error checking for existing unlabeled item for key '\(key)'. Status: \(unlabeledCheckStatus)")
          return false
      }
    } else if status != errSecSuccess {
      print("Error updating password for key '\(key)'. Status: \(status)")
      return false
    }
    return status == errSecSuccess
  }
}

func deletePassword(key: String) -> Bool {
  let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: key,
    kSecAttrLabel as String: keymasterLabelValue, // Ensure we only delete keymaster entries
    kSecMatchLimit as String: kSecMatchLimitOne
  ]
  let status = SecItemDelete(query as CFDictionary)
  return status == errSecSuccess
}

func getPassword(key: String) -> String? {
  let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: key,
    kSecAttrLabel as String: keymasterLabelValue, // Ensure we only get keymaster entries
    kSecMatchLimit as String: kSecMatchLimitOne,
    kSecReturnData as String: true
  ]
  var item: CFTypeRef?
  let status = SecItemCopyMatching(query as CFDictionary, &item)

  guard status == errSecSuccess,
    let passwordData = item as? Data,
    let password = String(data: passwordData, encoding: .utf8)
  else { return nil }

  return password
}

func listPasswords() -> Bool {
  let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrLabel as String: keymasterLabelValue, // Filter by the keymaster label
    kSecMatchLimit as String: kSecMatchLimitAll,
    kSecReturnAttributes as String: true,
    // kSecAttrSynchronizable as String: kSecAttrSynchronizableAny // Optional: uncomment to include iCloud keychain items
  ]

  var cfArrayResult: CFTypeRef?
  let status = SecItemCopyMatching(query as CFDictionary, &cfArrayResult)

  if status == errSecItemNotFound {
    print("No keymaster-managed passwords found in keychain.")
    return true // Successful operation, no items found
  }

  guard status == errSecSuccess else {
    // For more detailed error, you could use:
    // let errorDescription = SecCopyErrorMessageString(status, nil) as String? ?? "Unknown OSStatus"
    // print("Error fetching passwords from keychain. Status: \(status) (\(errorDescription))")
    print("Error fetching keymaster-managed passwords from keychain. Status: \(status)")
    return false // Operation failed
  }

  guard let retrievedItems = cfArrayResult as? [[String: Any]] else {
    // This should not happen if status is errSecSuccess with kSecMatchLimitAll
    print("Error: Unexpected data format received from keychain.")
    return false
  }

  if retrievedItems.isEmpty {
    print("No keymaster-managed passwords found in keychain.")
    return true
  }

  print("Stored keymaster-managed keys (services):")
  for item in retrievedItems {
    if let service = item[kSecAttrService as String] as? String {
      print("- \(service)")
    }
  }
  return true
}

func usage() {
  let programName = "keymaster"
  print("""
  Usage: \(programName) <command> [options]

  A simple command-line tool to manage passwords in the macOS Keychain,
  secured by Touch ID or Face ID.

  Commands:
    get <key>                     Retrieve and print the password for <key>.
    set <key> [<password>]        Set the password for <key>.
                                  If <password> is not provided, you will be prompted.
    delete <key>                  Delete the password for <key> from the keychain.
    list                          List all keys managed by \(programName).
    help, --help, -h              Show this help message.

  Options for 'set' command:
    --no-clobber                  Only set the password if <key> does not already exist.

  Examples:
    \(programName) set myServiceAPIKey                            # Set password for 'myServiceAPIKey', will prompt for password
    \(programName) set myServiceAPIKey S3cr3tP@sswOrd             # Set password for 'myServiceAPIKey' directly
    \(programName) set newAppKey --no-clobber                    # Set password for 'newAppKey' only if it doesn't exist, will prompt
    \(programName) set newAppKey S3cr3t --no-clobber             # Set password for 'newAppKey' directly, only if it doesn't exist
    \(programName) get myServiceAPIKey                            # Retrieve password for 'myServiceAPIKey'
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
    print("Error: No action specified.")
    usage()
    exit(EXIT_FAILURE)
  }

  let action = inputArgs[0]

  // Handle 'list' action separately as it doesn't require Touch ID
  if action == "list" {
    if inputArgs.count != 1 {
      print("Error: 'list' action does not take additional arguments.")
      usage()
      exit(EXIT_FAILURE)
    }
    if listPasswords() {
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
    print("This Mac doesn't support deviceOwnerAuthenticationWithBiometrics or it's not configured. Error: \(errorMsg)")
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
        print("Error: 'set' action requires a key.")
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
        print("Enter password for key '\(key)' [input is hidden]: ", terminator: "")
        fflush(stdout)
        if let cPassword = getpass("") {
            let enteredPassword = String(cString: cPassword)
            if enteredPassword.isEmpty {
                print("\nPassword input was empty. Operation cancelled, no password will be set.")
                exit(EXIT_FAILURE)
            }
            secret = enteredPassword
        } else {
            print("\nPassword input cancelled or failed. No password will be set.")
            exit(EXIT_FAILURE)
        }
    } else {
        // Too many arguments after processing key and flag
        print("Error: Invalid arguments for 'set' action.")
        print("See usage for correct format.")
        usage()
        exit(EXIT_FAILURE)
    }

    context.evaluatePolicy(policy, localizedReason: "set the password for \(key)") { success, authError in
      if success && authError == nil {
        if setPassword(key: key, password: secret, addOnly: noClobber) {
            print("Key \(key) has been successfully set in the keychain.")
            exit(EXIT_SUCCESS)
        } else {
          // setPassword function already prints specific error or "already exists" message
          exit(EXIT_FAILURE)
        }
      } else {
        let errorDescription = authError?.localizedDescription ?? "Unknown error"
        print("Authentication failed or was canceled: \(errorDescription)")
        exit(EXIT_FAILURE)
      }
    }
    dispatchMain()

  case "get":
    if inputArgs.count != 2 {
      print("Error: 'get' action requires a key.")
      usage()
      exit(EXIT_FAILURE)
    }
    let key = inputArgs[1]
    context.evaluatePolicy(policy, localizedReason: "access the password for \(key)") { success, authError in
      if success && authError == nil {
        guard let password = getPassword(key: key) else {
          print("Error getting password")
          exit(EXIT_FAILURE)
        }
        print(password)
        exit(EXIT_SUCCESS)
      } else {
        print("Authentication failed or was canceled: \(authError?.localizedDescription ?? "Unknown error")")
        exit(EXIT_FAILURE)
      }
    }
    dispatchMain()

  case "delete":
    if inputArgs.count != 2 {
      print("Error: 'delete' action requires a key.")
      usage()
      exit(EXIT_FAILURE)
    }
    let key = inputArgs[1]
    context.evaluatePolicy(policy, localizedReason: "delete the password for \(key)") { success, authError in
      if success && authError == nil {
        guard deletePassword(key: key) else {
          print("Error deleting password")
          exit(EXIT_FAILURE)
        }
        print("Key \(key) has been successfully deleted from the keychain")
        exit(EXIT_SUCCESS)
      } else {
        print("Authentication failed or was canceled: \(authError?.localizedDescription ?? "Unknown error")")
        exit(EXIT_FAILURE)
      }
    }
    dispatchMain()

  default:
    print("Error: Unknown action '\(action)'.")
    usage()
    exit(EXIT_FAILURE)
  }
}

main()