import Foundation


/// Namespace for ASN.1 data structures.
public enum ASN1 {

    /// Represents a single node in an ASN.1 tree.
    public enum Node : Equatable {
        case boolean(value: Bool)
        case integer(value: Integer)
        case bitString(value: BitString)
        case octetString(value: OctetString)
        case null
        case objectIdentifier(value: ObjectIdentifier)
        case utf8String(value: String)
        case sequence(components: [Node])
        case set(components: [Node])
        case numericString(value: String)
        case printableString(value: String)
        case ia5String(value: String)
        case utcTime(value: Date)
        case universalString(value: String)
        case bmpString(value: String)
        case otherPrimitive(tag: Tag, data: Data)
        case otherConstructed(tag: Tag, components: [Node])
    }
    
    /// Represents an ASN.1 tag, defining the type of a node.
    public struct Tag : Equatable {
        let `class`: TagClass
        let constructed: Bool
        let number: Int
    }
    
    /// Represents one of 4 ASN.1 tag classes.
    public enum TagClass : String {
        case universal
        case application
        case contextSpecific
        case `private`
    }
    
    /// Represents an ASN.1 integer of any size. The integer is stored as a ``Data`` in big-endian format.
    public struct Integer : Equatable {
        let data: Data
    }

    /// Represents an ASN.1 bit string. It is stored as a ``Data`` padded with 0 bits (``unusedBits``).
    public struct BitString : Equatable {
        let data: Data
        let unusedBits: Int
    }
    
    /// Represents an ASN.1 octet string. It is stored as a ``Data``.
    public struct OctetString : Equatable {
        let data: Data
    }
    
    /// Represents an ASN.1 object identifier. It is stored as an array if ints.
    public struct ObjectIdentifier : Equatable {
        let identifiers: [Int]
    }

}


extension ASN1.Node {
    
    /// Gets the string value of this node, if the node is any of the known string nodes.
    public var stringValue: String? {
        return switch self {
        case .utf8String(let value): value
        case .numericString(let value): value
        case .printableString(let value): value
        case .ia5String(let value): value
        case .universalString(let value): value
        case .bmpString(let value): value
        default: nil
        }
    }
    
}


extension ASN1.Node : CustomStringConvertible {
    
    public var description: String {
        return description(indentation: 0)
    }
    
    private func description(indentation: Int) -> String {
        let tag: ASN1.Tag
        let components: [ASN1.Node]
        let description: String?
        switch self {
        case .boolean(let value):
            tag = .boolean
            components = []
            description = value.description
        case .integer(let value):
            tag = .integer
            components = []
            description = value.description
        case .bitString(let value):
            tag = .bitString
            components = []
            description = value.description
        case .octetString(let value):
            tag = .octetString
            components = []
            description = value.description
        case .null:
            tag = .null
            components = []
            description = nil
        case .objectIdentifier(let value):
            tag = .objectIdentifier
            components = []
            description = value.description
        case .utf8String(let value):
            tag = .utf8String
            components = []
            description = quote(string: value)
        case .sequence(let comp):
            tag = .sequence
            components = comp
            description = format(componentCount: comp.count)
        case .set(let comp):
            tag = .set
            components = comp
            description = format(componentCount: comp.count)
        case .numericString(let value):
            tag = .numericString
            components = []
            description = quote(string: value)
        case .printableString(let value):
            tag = .printableString
            components = []
            description = quote(string: value)
        case .ia5String(let value):
            tag = .ia5String
            components = []
            description = quote(string: value)
        case .utcTime(let value):
            tag = .utcTime
            components = []
            description = format(date: value)
        case .universalString(let value):
            tag = .universalString
            components = []
            description = quote(string: value)
        case .bmpString(let value):
            tag = .bmpString
            components = []
            description = quote(string: value)
        case .otherPrimitive(let t, let data):
            tag = t
            components = []
            description = "(\(data.count) bytes) 0x\(data.toHex(uppercase: true))"
        case .otherConstructed(let t, let comp):
            tag = t
            components = comp
            description = format(componentCount: comp.count)
        }
        
        var result = "\(String(repeating: " ", count: indentation))\(tag)"
        if let description {
            result += ": \(description)"
        }
        for component in components {
            result += "\n"
            result += component.description(indentation: indentation + 4)
        }
        return result
    }
    
    private func quote(string: String) -> String {
        let escaped = string
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\n", with: "\\n")
        return "\"\(escaped)\""
    }
    
    private func format(date: Date) -> String {
        return date.ISO8601Format()
    }
    
    private func format(componentCount: Int) -> String {
        return "\(componentCount) components"
    }
    
}


extension ASN1.Tag {
    
    public static let boolean = ASN1.Tag(class: .universal, constructed: false, number: 1)
    public static let integer = ASN1.Tag(class: .universal, constructed: false, number: 2)
    public static let bitString = ASN1.Tag(class: .universal, constructed: false, number: 3)
    public static let octetString = ASN1.Tag(class: .universal, constructed: false, number: 4)
    public static let null = ASN1.Tag(class: .universal, constructed: false, number: 5)
    public static let objectIdentifier = ASN1.Tag(class: .universal, constructed: false, number: 6)
    public static let objectDescriptor = ASN1.Tag(class: .universal, constructed: false, number: 7)
    public static let external = ASN1.Tag(class: .universal, constructed: true, number: 8)
    public static let real = ASN1.Tag(class: .universal, constructed: false, number: 9)
    public static let enumerated = ASN1.Tag(class: .universal, constructed: false, number: 10)
    public static let embeddedPDV = ASN1.Tag(class: .universal, constructed: true, number: 11)
    public static let utf8String = ASN1.Tag(class: .universal, constructed: false, number: 12)
    public static let relativeOID = ASN1.Tag(class: .universal, constructed: false, number: 13)
    public static let time = ASN1.Tag(class: .universal, constructed: false, number: 14)
    public static let sequence = ASN1.Tag(class: .universal, constructed: true, number: 16)
    public static let set = ASN1.Tag(class: .universal, constructed: true, number: 17)
    public static let numericString = ASN1.Tag(class: .universal, constructed: false, number: 18)
    public static let printableString = ASN1.Tag(class: .universal, constructed: false, number: 19)
    public static let teletexString = ASN1.Tag(class: .universal, constructed: false, number: 20)
    public static let ia5String = ASN1.Tag(class: .universal, constructed: false, number: 22)
    public static let videotexString = ASN1.Tag(class: .universal, constructed: false, number: 21)
    public static let utcTime = ASN1.Tag(class: .universal, constructed: false, number: 23)
    public static let generalizedTime = ASN1.Tag(class: .universal, constructed: false, number: 24)
    public static let graphicString = ASN1.Tag(class: .universal, constructed: false, number: 25)
    public static let visibleString = ASN1.Tag(class: .universal, constructed: false, number: 26)
    public static let generalString = ASN1.Tag(class: .universal, constructed: false, number: 27)
    public static let universalString = ASN1.Tag(class: .universal, constructed: false, number: 28)
    public static let characterString = ASN1.Tag(class: .universal, constructed: true, number: 29)
    public static let bmpString = ASN1.Tag(class: .universal, constructed: false, number: 30)
    public static let date = ASN1.Tag(class: .universal, constructed: false, number: 31)
    public static let timeOfDay = ASN1.Tag(class: .universal, constructed: false, number: 32)
    public static let dateTime = ASN1.Tag(class: .universal, constructed: false, number: 33)
    public static let duration = ASN1.Tag(class: .universal, constructed: false, number: 34)
    public static let oidIRI = ASN1.Tag(class: .universal, constructed: false, number: 35)
    public static let relativeOIDIRI = ASN1.Tag(class: .universal, constructed: false, number: 36)

    private static let universalTagLookup: [(tag: ASN1.Tag, name: String)?] = {
        let universalTags: [(tag: ASN1.Tag, name: String)] = [
            (boolean, "BOOLEAN"),
            (integer, "INTEGER"),
            (bitString, "BIT STRING"),
            (octetString, "OCTET STRING"),
            (null, "NULL"),
            (objectIdentifier, "OBJECT IDENTIFIER"),
            (objectDescriptor, "ObjectDescriptor"),
            (external, "EXTERNAL"),
            (real, "REAL"),
            (enumerated, "ENUMERATED"),
            (embeddedPDV, "EMBEDDED PDV"),
            (utf8String, "UTF8String"),
            (relativeOID, "RELATIVE-OID"),
            (time, "TIME"),
            (sequence, "SEQUENCE"),
            (set, "SET"),
            (numericString, "NumericString"),
            (printableString, "PrintableString"),
            (teletexString, "TeletexString"),
            (ia5String, "IA5String"),
            (videotexString, "VideotexString"),
            (utcTime, "UTCTime"),
            (generalizedTime, "GeneralizedTime"),
            (graphicString, "GraphicString"),
            (visibleString, "VisibleString"),
            (generalString, "GeneralString"),
            (universalString, "UniversalString"),
            (characterString, "CHARACTER STRING"),
            (bmpString, "BMPString"),
            (date, "DATE"),
            (timeOfDay, "TIME-OF-DAY"),
            (dateTime, "DATE-TIME"),
            (duration, "DURATION"),
            (oidIRI, "OID-IRI"),
            (relativeOIDIRI, "RELATIVE-OID-IRI")
        ]
        var lookup = [(tag: ASN1.Tag, name: String)?](
            repeating: nil,
            count: universalTags.max { lhs, rhs in lhs.tag.number < rhs.tag.number }!.tag.number + 1
        )
        for universalTag in universalTags {
            lookup[universalTag.tag.number] = universalTag
        }
        return lookup
    }()
    
    public static func universalTag(for number: Int) -> (tag: ASN1.Tag, name: String)? {
        guard universalTagLookup.indices ~= number else { return nil }
        return universalTagLookup[number]
    }
    
}


extension ASN1.Tag : CustomStringConvertible {
    public var description: String {
        if `class` == .universal, let universalTag = Self.universalTag(for: number) {
            return switch constructed {
            case universalTag.tag.constructed: universalTag.name
            case true: "\(universalTag.name) (constructed)"
            case false: "\(universalTag.name) (primitive)"
            }
        } else {
            return "[\(number)] (\(`class`), \(constructed ? "constructed" : "primitive"))"
        }
    }
}


extension ASN1.TagClass : CustomStringConvertible {
    public var description: String { rawValue }
}


extension ASN1.Integer {
    
    /// Gets the ``Int`` value for this integer, if it fits in the memory layout of an int.
    public var intValue: Int? {
        guard data.count <= MemoryLayout<Int>.size else { return nil }
        var intValue = 0
        for (index, byte) in data.enumerated() {
            if index == 0 {
                intValue = Int(Int8(bitPattern: byte))
            } else {
                intValue = (intValue << 8) | Int(byte)
            }
        }
        return intValue
    }
    
}

extension ASN1.Integer : CustomStringConvertible {
    public var description: String {
        let stringValue: String
        if let intValue {
            stringValue = String(intValue)
        } else {
            stringValue = "0x\(data.toHex(uppercase: true))"
        }
        return "(\(data.count << 3) bit) \(stringValue)"
    }
}


extension ASN1.BitString : CustomStringConvertible {
    public var description: String {
        return "(\((data.count << 3) - unusedBits) bits) 0x\(data.toHex(uppercase: true))"
    }
}


extension ASN1.OctetString : CustomStringConvertible {
    public var description: String {
        return "(\(data.count) bytes) 0x\(data.toHex(uppercase: true))"
    }
}


extension ASN1.ObjectIdentifier {
    
    public static let rsaEncryption = ASN1.ObjectIdentifier(string: "1.2.840.113549.1.1.1")!
    public static let ecPublicKey = ASN1.ObjectIdentifier(string: "1.2.840.10045.2.1")!

    /// Initializes a new object identifier ussing 'dotted' notation.
    public init?(string: String) {
        var identifiers = [Int]()
        for stringIdentifier in string.components(separatedBy: ".") {
            guard let identifier = Int(stringIdentifier), identifier >= 0 else {
                return nil
            }
            identifiers.append(identifier)
        }
        guard identifiers.count >= 2 else {
            return nil
        }
        self.identifiers = identifiers
    }
    
    /// Gets the more common 'dotted' notation, such as "1.2.840.113549.1.1.1".
    public var dottedNotation: String {
        return identifiers.map { String($0) }.joined(separator: ".")
    }
    
}

extension ASN1.ObjectIdentifier : CustomStringConvertible {
    public var description: String { dottedNotation }
}
