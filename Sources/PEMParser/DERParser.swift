import Foundation


/**
 * Simple implementation of a parser of the DER format.
 *
 * Initially based on https://github.com/TakeScoop/SwiftyRSA/blob/master/Source/Asn1Parser.swift,
 * but later improved with information from https://luca.ntop.org/Teaching/Appunti/asn1.html
 * and https://www.oss.com/asn1/resources/asn1-made-simple/introduction.html
 */
public enum DERParser {
    
    // MARK: Public static functions
    
    /// Parses the given DER formatted data and returns the root ASN.1 node.
    public static func parse(data: Data) throws -> ASN1.Node {
        return try parse(data: data, in: data.indices)
    }
    
    /// Parses the given DER formatted data within the range and returns the root ASN.1 node.
    public static func parse(data: Data, in range: Range<Data.Index>) throws -> ASN1.Node {
        guard range.startIndex >= data.startIndex && range.endIndex <= data.endIndex else {
            throw ParsingError.invalidDataRange
        }
        guard !data.isEmpty else {
            throw ParsingError.unexpectedEndOfData
        }
        return try data.withUnsafeBytes { ptr in
            try ptr.withMemoryRebound(to: UInt8.self) { bytes in
                let (node, parsedByteCount) = try parseNode(bytes: bytes[range])
                guard parsedByteCount == range.count else {
                    throw ParsingError.unexpectedDataRemaining
                }
                return node
            }
        }
    }
    
    
    // MARK: Private static functions
    
    private static func parseNode(bytes: Slice<UnsafeBufferPointer<UInt8>>) throws -> (ASN1.Node, Int) {
        var index = bytes.startIndex
        let tag = try parseTag(bytes: bytes, index: &index)
        let size = try parseSize(bytes: bytes, index: &index)
        
        let node: ASN1.Node = switch tag {
        case .boolean: try parseBoolean(bytes: bytes, index: &index, size: size)
        case .integer: try parseInteger(bytes: bytes, index: &index, size: size)
        case .bitString: try parseBitString(bytes: bytes, index: &index, size: size)
        case .octetString: try parseOctetString(bytes: bytes, index: &index, size: size)
        case .null: try parseNull(bytes: bytes, index: &index, size: size)
        case .objectIdentifier: try parseObjectIdentifier(bytes: bytes, index: &index, size: size)
        case .utf8String: try parseUTF8String(bytes: bytes, index: &index, size: size)
        case .sequence: .sequence(components: try parseComponents(bytes: bytes, index: &index, size: size))
        case .set: .set(components: try parseComponents(bytes: bytes, index: &index, size: size))
        case .numericString: try parseNumericString(bytes: bytes, index: &index, size: size)
        case .printableString: try parsePrintableString(bytes: bytes, index: &index, size: size)
        case .ia5String: try parseIA5String(bytes: bytes, index: &index, size: size)
        case .utcTime: try parseUTCTime(bytes: bytes, index: &index, size: size)
        case .universalString: try parseUniversalString(bytes: bytes, index: &index, size: size)
        case .bmpString: try parseBMPString(bytes: bytes, index: &index, size: size)
        default: try parseOther(tag: tag, bytes: bytes, index: &index, size: size)
        }
        
        return (node, index - bytes.startIndex)
    }
    
    private static func parseComponents(bytes: Slice<UnsafeBufferPointer<UInt8>>, index: inout Int, size: Int) throws -> [ASN1.Node] {
        var components = [ASN1.Node]()
        let endIndex = index + size
        while index < endIndex {
            let (node, parsedByteCount) = try parseNode(bytes: bytes[index ..< endIndex])
            components.append(node)
            index += parsedByteCount
        }
        return components
    }
    
    private static func parseTag(bytes: Slice<UnsafeBufferPointer<UInt8>>, index: inout Int) throws -> ASN1.Tag {
        let firstByte = try readByte(bytes: bytes, index: &index)
        
        let `class`: ASN1.TagClass = switch firstByte >> 6 {
        case 0: .universal
        case 1: .application
        case 2: .contextSpecific
        case 3: .private
        default: fatalError()
        }
        
        let constructed = firstByte & 0x20 != 0
        
        var number = Int(firstByte & 0x1f)
        if number == 0x1f {
            number = 0
            var nextByte: UInt8
            repeat {
                guard number <= Int.max >> 7 else {
                    throw ParsingError.invalidTagNumber
                }
                nextByte = try readByte(bytes: bytes, index: &index)
                number = (number << 7) | Int(nextByte & 0x7f)
            } while nextByte & 0x80 != 0
        }
        
        return ASN1.Tag(
            class: `class`,
            constructed: constructed,
            number: number
        )
    }
        
    private static func parseSize(bytes: Slice<UnsafeBufferPointer<UInt8>>, index: inout Int) throws -> Int {
        let firstByte = try readByte(bytes: bytes, index: &index)
        
        if firstByte < 0x80 {
            return Int(firstByte)
        }
        
        var size = 0
        for _ in 0 ..< firstByte & 0x7f {
            guard size <= Int.max >> 8 else {
                throw ParsingError.invalidSize
            }
            let nextByte = try readByte(bytes: bytes, index: &index)
            size = (size << 8) | Int(nextByte)
        }
        
        guard size >= 0x80 else {
            throw ParsingError.invalidSize
        }
        
        return size
    }
    
    private static func parseBoolean(bytes: Slice<UnsafeBufferPointer<UInt8>>, index: inout Int, size: Int) throws -> ASN1.Node {
        guard size == 1 else { throw ParsingError.invalidBooleanValue }
        let value = switch try readByte(bytes: bytes, index: &index) {
        case 0x00: false
        case 0xff: true
        default: throw ParsingError.invalidBooleanValue
        }
        return .boolean(value: value)
    }
    
    private static func parseInteger(bytes: Slice<UnsafeBufferPointer<UInt8>>, index: inout Int, size: Int) throws -> ASN1.Node {
        guard size > 0 else { throw ParsingError.invalidIntegerValue }
        let value = ASN1.Integer(data: try readData(bytes: bytes, index: &index, size: size))
        return .integer(value: value)
    }
    
    private static func parseBitString(bytes: Slice<UnsafeBufferPointer<UInt8>>, index: inout Int, size: Int) throws -> ASN1.Node {
        let unusedBits = Int(try readByte(bytes: bytes, index: &index))
        let data: Data
        if size == 1 {
            guard unusedBits == 0 else { throw ParsingError.invalidBitStringValue }
            data = Data()
        } else {
            guard unusedBits <= 7 else { throw ParsingError.invalidBooleanValue }
            data = try readData(bytes: bytes, index: &index, size: size - 1)
        }
        let value = ASN1.BitString(data: data, unusedBits: unusedBits)
        return .bitString(value: value)
    }
    
    private static func parseOctetString(bytes: Slice<UnsafeBufferPointer<UInt8>>, index: inout Int, size: Int) throws -> ASN1.Node {
        let data: Data
        if size == 0 {
            data = Data()
        } else {
            data = try readData(bytes: bytes, index: &index, size: size)
        }
        let value = ASN1.OctetString(data: data)
        return .octetString(value: value)
    }
    
    private static func parseNull(bytes: Slice<UnsafeBufferPointer<UInt8>>, index: inout Int, size: Int) throws -> ASN1.Node {
        guard size == 0 else { throw ParsingError.invalidNullValue }
        return .null
    }
    
    private static func parseObjectIdentifier(bytes: Slice<UnsafeBufferPointer<UInt8>>, index: inout Int, size: Int) throws -> ASN1.Node {
        let endIndex = index + size
        var identifiers = [Int]()
        
        guard size > 0 else { throw ParsingError.invalidObjectIdentifierValue }
        let firstByte = try readByte(bytes: bytes, index: &index)
        identifiers.append(Int(firstByte / 40))
        identifiers.append(Int(firstByte % 40))
        
        while index < endIndex {
            var identifier = 0
            var nextByte: UInt8
            repeat {
                guard identifier <= Int.max >> 7 && index < endIndex else {
                    throw ParsingError.invalidObjectIdentifierValue
                }
                nextByte = try readByte(bytes: bytes, index: &index)
                identifier = (identifier << 7) | Int(nextByte & 0x7f)
            } while nextByte & 0x80 != 0
            identifiers.append(identifier)
        }
        
        let value = ASN1.ObjectIdentifier(identifiers: identifiers)
        return .objectIdentifier(value: value)
    }
    
    private static func parseUTF8String(bytes: Slice<UnsafeBufferPointer<UInt8>>, index: inout Int, size: Int) throws -> ASN1.Node {
        let data = try readData(bytes: bytes, index: &index, size: size)
        guard let value = String(data: data, encoding: .utf8) else { throw ParsingError.invalidUTF8StringValue }
        return .utf8String(value: value)
    }
    
    private static func parseNumericString(bytes: Slice<UnsafeBufferPointer<UInt8>>, index: inout Int, size: Int) throws -> ASN1.Node {
        let data = try readData(bytes: bytes, index: &index, size: size)
        guard let value = String(data: data, encoding: .ascii) else { throw ParsingError.invalidNumericStringValue }
        return .numericString(value: value)
    }
    
    private static func parsePrintableString(bytes: Slice<UnsafeBufferPointer<UInt8>>, index: inout Int, size: Int) throws -> ASN1.Node {
        let data = try readData(bytes: bytes, index: &index, size: size)
        guard let value = String(data: data, encoding: .ascii) else { throw ParsingError.invalidPrintableStringValue }
        return .printableString(value: value)
    }
    
    private static func parseIA5String(bytes: Slice<UnsafeBufferPointer<UInt8>>, index: inout Int, size: Int) throws -> ASN1.Node {
        let data = try readData(bytes: bytes, index: &index, size: size)
        guard let value = String(data: data, encoding: .ascii) else { throw ParsingError.invalidIA5StringValue }
        return .ia5String(value: value)
    }
    
    private static func parseUTCTime(bytes: Slice<UnsafeBufferPointer<UInt8>>, index: inout Int, size: Int) throws -> ASN1.Node {
        let data = try readData(bytes: bytes, index: &index, size: size)
        guard
            let stringValue = String(data: data, encoding: .ascii),
            let match = stringValue.wholeMatch(of: #/^(?<YY>[0-9]{2})(?<MM>[0-9]{2})(?<DD>[0-9]{2})(?<hh>[0-9]{2})(?<mm>[0-9]{2})(?<ss>[0-9]{2})?(?:(?<z>Z)|(?<tz>(?:\+|-)[0-9]{4}))$/#)
        else { throw ParsingError.invalidUTCTimeValue }
        
        var components = DateComponents()
        let twoDigitYear = Int(match.output.YY)!
        components.year = twoDigitYear > 50 ? 1900 + twoDigitYear : 2000 + twoDigitYear
        components.month = Int(match.output.MM)!
        components.day = Int(match.output.DD)!
        components.hour = Int(match.output.hh)!
        components.minute = Int(match.output.mm)!
        if let ss = match.output.ss {
            components.second = Int(ss)!
        }
        if let _ = match.output.z {
            components.timeZone = .gmt
        }
        if let tz = match.output.tz {
            let intTZ = Int(tz)!
            components.timeZone = .init(secondsFromGMT: (intTZ / 100 * 3600) + (intTZ % 100 * 60))
        }
        
        guard let value = Calendar(identifier: .gregorian).date(from: components) else {
            throw ParsingError.invalidUTCTimeValue
        }
        return .utcTime(value: value)
    }
    
    private static func parseUniversalString(bytes: Slice<UnsafeBufferPointer<UInt8>>, index: inout Int, size: Int) throws -> ASN1.Node {
        let data = try readData(bytes: bytes, index: &index, size: size)
        guard let value = String(data: data, encoding: .utf32BigEndian) else { throw ParsingError.invalidUniversalStringValue }
        return .universalString(value: value)
    }
    
    private static func parseBMPString(bytes: Slice<UnsafeBufferPointer<UInt8>>, index: inout Int, size: Int) throws -> ASN1.Node {
        let data = try readData(bytes: bytes, index: &index, size: size)
        guard let value = String(data: data, encoding: .utf16BigEndian) else { throw ParsingError.invalidBMPStringValue }
        return .bmpString(value: value)
    }
    
    private static func parseOther(tag: ASN1.Tag, bytes: Slice<UnsafeBufferPointer<UInt8>>, index: inout Int, size: Int) throws -> ASN1.Node {
        if tag.constructed {
            return .otherConstructed(tag: tag, components: try parseComponents(bytes: bytes, index: &index, size: size))
        } else {
            return .otherPrimitive(tag: tag, data: try readData(bytes: bytes, index: &index, size: size))
        }
    }
    
    @inline(__always) private static func readByte(bytes: Slice<UnsafeBufferPointer<UInt8>>, index: inout Int) throws -> UInt8 {
        guard index < bytes.endIndex else { throw ParsingError.unexpectedEndOfData }
        let byte = bytes[index]
        bytes.formIndex(after: &index)
        return byte
    }
    
    private static func readData(bytes: Slice<UnsafeBufferPointer<UInt8>>, index: inout Int, size: Int) throws -> Data {
        guard size > 0 else { return Data() }
        guard index + size <= bytes.endIndex else { throw ParsingError.unexpectedEndOfData }
        let data = bytes[index ..< index + size].withUnsafeBytes { buffer in
            buffer.withMemoryRebound(to: UInt8.self) { Data(buffer: $0) }
        }
        index += size
        return data
    }
    
    
    // MARK: Nested types
        
    public enum ParsingError : Error {
        case invalidDataRange
        case unexpectedEndOfData
        case unexpectedDataRemaining
        case invalidSize
        case invalidTagNumber
        case invalidBooleanValue
        case invalidIntegerValue
        case invalidBitStringValue
        case invalidOctetStringValue
        case invalidNullValue
        case invalidObjectIdentifierValue
        case invalidUTF8StringValue
        case invalidNumericStringValue
        case invalidPrintableStringValue
        case invalidIA5StringValue
        case invalidUTCTimeValue
        case invalidUniversalStringValue
        case invalidBMPStringValue
    }
    
}
