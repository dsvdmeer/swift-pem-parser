import Foundation
import Security


/**
 * Parser for PEM files. Can parse certificates, public keys and private keys.
 * Also has functions for directly parsing the Base64 instead of a whole file.
 */
public enum PEMParser {
    
    // MARK: Public static functions
    
    /// Parses the specified Base64 string, ignoring whitespace.
    public static func parse(base64: String) throws -> Data {
        guard let data = Data(base64Encoded: base64.filter { !$0.isWhitespace }) else {
            throw ParsingError.invalidBase64
        }
        return data
    }
    
    /// Parses the PEM file at the specified URL. The file is decoded using UTF-8.
    public static func parseFile(at url: URL) throws -> [FileEntry] {
        let string = try String(contentsOf: url, encoding: .utf8)
        return try parseFile(string: string)
    }
    
    /// Parses a PEM file that has already been read into memory. The file is decoded using UTF-8.
    public static func parseFile(data: Data) throws -> [FileEntry] {
        guard let string = String(data: data, encoding: .utf8) else {
            throw ParsingError.invalidUTF8
        }
        return try parseFile(string: string)
    }
    
    /// Parses a PEM file that has already been converted to a string
    public static func parseFile(string: String) throws -> [FileEntry] {
        let beginMarkerPrefix = "-----BEGIN "
        let endMarkerPrefix = "-----END "
        let markerSuffix = "-----"
        
        var result = [FileEntry]()
        var currentType: String?
        var base64 = ""
        for line in string.components(separatedBy: .newlines) {
            guard !line.isEmpty else { continue }
            if let currentType {
                if line.hasPrefix(endMarkerPrefix) && line.hasSuffix(markerSuffix) {
                    let endType = extractType(from: line, prefix: endMarkerPrefix, suffix: markerSuffix)
                    guard endType == currentType else {
                        throw ParsingError.invalidPEMFormat
                    }
                    let fileEntry: FileEntry? = switch currentType {
                    case "CERTIFICATE": .certificate(try parseCertificate(base64: base64))
                    case "PUBLIC KEY": .publicKey(try parsePublicKey(base64: base64))
                    case "PRIVATE KEY": .privateKey(try parsePrivateKey(base64: base64))
                    default: nil
                    }
                    if let fileEntry {
                        result.append(fileEntry)
                    }
                } else {
                    base64 += line
                }
            } else if line.hasPrefix(beginMarkerPrefix) && line.hasSuffix(markerSuffix) {
                currentType = extractType(from: line, prefix: beginMarkerPrefix, suffix: markerSuffix)
            }
        }
        
        return result
    }
    
    /// Parses a PEM certificate in Base64 format.
    public static func parseCertificate(base64: String) throws -> SecCertificate {
        return try parseCertificate(data: parse(base64: base64))
    }
    
    /// Parses a PEM certificate as data.
    public static func parseCertificate(data: Data) throws -> SecCertificate {
        guard let certificate = SecCertificateCreateWithData(nil, data as CFData) else {
            throw ParsingError.invalidCertificateFormat
        }
        return certificate
    }
    
    /// Parses a PEM public key in Base64 format.
    public static func parsePublicKey(base64: String) throws -> SecKey {
        return try parsePublicKey(data: parse(base64: base64))
    }
    
    /// Parses a PEM public key as data.
    public static func parsePublicKey(data: Data) throws -> SecKey {
        guard
            case .sequence(let rootComponents) = try DERParser.parse(data: data), rootComponents.count == 2,
            case .sequence(let algorithmComponents) = rootComponents[0], algorithmComponents.count == 2,
            case .objectIdentifier(let algorithmIdentifier) = algorithmComponents[0],
            case .bitString(let bitString) = rootComponents[1], bitString.unusedBits == 0
        else { throw ParsingError.invalidPublicKeyFormat }
        
        let type: CFString = switch algorithmIdentifier {
        case .rsaEncryption: kSecAttrKeyTypeRSA
        case .ecPublicKey: kSecAttrKeyTypeECSECPrimeRandom
        default: throw ParsingError.unsupportedPublicKeyAlgorithm
        }
        
        return try createKey(data: bitString.data, class: kSecAttrKeyClassPublic, type: type)
    }

    /// Parses a PEM private key in Base64 format.
    public static func parsePrivateKey(base64: String) throws -> SecKey {
        return try parsePrivateKey(data: parse(base64: base64))
    }
    
    /// Parses a PEM private key as data.
    public static func parsePrivateKey(data: Data) throws -> SecKey {
        guard
            case .sequence(let rootComponents) = try DERParser.parse(data: data), rootComponents.count >= 3,
            case .integer(let version) = rootComponents[0], version.intValue == 0,
            case .sequence(let algorithmComponents) = rootComponents[1], algorithmComponents.count == 2,
            case .objectIdentifier(let algorithmIdentifier) = algorithmComponents[0],
            case .octetString(let octetString) = rootComponents[2]
        else { throw ParsingError.invalidPrivateKeyFormat }
        
        let type: CFString = switch algorithmIdentifier {
        case .rsaEncryption: kSecAttrKeyTypeRSA
        default: throw ParsingError.unsupportedPrivateKeyAlgorithm
        }

        return try createKey(data: octetString.data, class: kSecAttrKeyClassPrivate, type: type)
    }
    
    
    // MARK: Private static functions
    
    private static func extractType(from string: String, prefix: String, suffix: String) -> String {
        let startIndex = string.index(string.startIndex, offsetBy: prefix.count)
        let endIndex = string.index(string.endIndex, offsetBy: -suffix.count)
        return String(string[startIndex ..< endIndex])
    }
    
    private static func createKey(data: Data, class: CFString, type: CFString) throws -> SecKey {
        var unmanagedError: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(
            data as CFData,
            [kSecAttrKeyClass: `class`, kSecAttrKeyType: type] as CFDictionary,
            &unmanagedError
        ) else {
            guard let error = unmanagedError?.takeUnretainedValue() else {
                fatalError("SecKeyCreateWithData returned neither a key nor an error")
            }
            throw error
        }
        return key
    }
        

    // MARK: Nested types
    
    /// Represents an entry in a PEM file.
    public enum FileEntry {
        case certificate(SecCertificate)
        case publicKey(SecKey)
        case privateKey(SecKey)
    }
    
    public enum ParsingError : Error {
        case invalidBase64
        case invalidUTF8
        case invalidPEMFormat
        case invalidCertificateFormat
        case invalidPublicKeyFormat
        case unsupportedPublicKeyAlgorithm
        case invalidPrivateKeyFormat
        case unsupportedPrivateKeyAlgorithm
        case unknownKeyCreationError
    }
    
}
