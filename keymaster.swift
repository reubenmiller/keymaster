// Keymaster, access Keychain secrets guarded by TouchID
//
import Darwin // For getpass()
import Foundation
import LocalAuthentication

// Policy for Touch ID/Face ID authentication
let policy = LAPolicy.deviceOwnerAuthenticationWithBiometrics
// Unique label to identify keychain entries managed by this keymaster tool
let keymasterLabelValue = "com.github.reubenmiller.keymaster.entry"

func setPassword(key: String, password: String) -> Bool {
  // Attributes to update or add for the keychain item
  let valueData = password.data(using: .utf8)!

  // Query to find an existing item managed by keymaster
  let queryForUpdate: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: key,
    kSecAttrLabel as String: keymasterLabelValue // Ensure we only target keymaster entries
  ]

  let attributesToUpdate: [String: Any] = [
    kSecValueData as String: valueData
  ]

  // Try to update an existing item managed by keymaster
  var status = SecItemUpdate(queryForUpdate as CFDictionary, attributesToUpdate as CFDictionary)

  if status == errSecItemNotFound {
    // No item found with our key AND label.
    // Check if an item with the same service key exists *without* our label.
    let queryForUnlabeledExisting: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: key
        // No kSecAttrLabel here
    ]
    var item: CFTypeRef?
    let unlabeledCheckStatus = SecItemCopyMatching(queryForUnlabeledExisting as CFDictionary, &item)

    if unlabeledCheckStatus == errSecSuccess {
        // An item with this service key exists but is not managed by this version of keymaster.
        print("Error: An item with key '\(key)' already exists but is not managed by keymaster (it lacks the keymaster label).")
        print("To manage this item with keymaster, it must first be removed or updated to include the keymaster label by other means.")
        return false // Indicate failure
    } else if unlabeledCheckStatus == errSecItemNotFound {
        // Good, no conflicting unlabeled item. Proceed to add a new, labeled item.
        let attributesForAdd: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: key,
            kSecAttrLabel as String: keymasterLabelValue, // Add the keymaster label
            kSecValueData as String: valueData
        ]
        status = SecItemAdd(attributesForAdd as CFDictionary, nil)
        if status == errSecDuplicateItem {
            print("Error: Failed to add password for key '\(key)'. A duplicate item might exist despite checks. Status: \(status)")
            return false
        }
    } else {
        // Some other error occurred while checking for an unlabeled item.
        print("Error checking for existing unlabeled item for key '\(key)'. Status: \(unlabeledCheckStatus)")
        return false
    }
  } else if status != errSecSuccess {
    // SecItemUpdate failed for a reason other than errSecItemNotFound
    print("Error updating password for key '\(key)'. Status: \(status)")
    return false
  }
  return status == errSecSuccess
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
  print("Usage: keymaster <action> <key> [<secret>]")
  print("keymaster get <key>")
  print("keymaster set <key> <secret>")
  print("keymaster delete <key>")
  print("keymaster list")
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
    let key: String
    let secret: String

    if inputArgs.count == 3 { // keymaster set <key> <secret>
      key = inputArgs[1]
      secret = inputArgs[2]
    } else if inputArgs.count == 2 { // keymaster set <key> -> prompt for secret
      key = inputArgs[1]
      print("Enter password for key '\(key)' [input is hidden]: ", terminator: "")
      // Ensure stdout is flushed so the prompt appears before readLine waits for input.
      // For getpass, it's good practice to flush stdout.
      fflush(stdout)

      if let cPassword = getpass("") { // getpass prompt is often ignored, so we print our own.
        let enteredPassword = String(cString: cPassword)
        // It's good practice to clear the memory used by getpass if possible,
        // though getpass itself often uses a static buffer.
        // For this example, we'll rely on ARC for the Swift string.
        if enteredPassword.isEmpty {
            // User pressed Enter without typing anything.
            print("\nPassword input was empty. Operation cancelled, no password will be set.")
            exit(EXIT_FAILURE)
        }
        secret = enteredPassword
      } else {
        // getpass() returned NULL, e.g., due to EOF (Ctrl+D) or an error.
        print("\nPassword input cancelled or failed. No password will be set.")
        exit(EXIT_FAILURE)
      }
    } else {
      print("Error: 'set' action requires a key, and optionally a secret on the command line.")
      print("If the secret is not provided as an argument, you will be prompted for it.")
      usage()
      exit(EXIT_FAILURE)
    }
    context.evaluatePolicy(policy, localizedReason: "set the password for \(key)") { success, authError in
      if success && authError == nil {
        guard setPassword(key: key, password: secret) else {
          print("Error setting password")
          exit(EXIT_FAILURE)
        }
        print("Key \(key) has been successfully set in the keychain")
        exit(EXIT_SUCCESS)
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