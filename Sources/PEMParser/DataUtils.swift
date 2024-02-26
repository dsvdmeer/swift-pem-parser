import Foundation


extension Data {
    
    private static let lowercaseHexAlphabet = Array("0123456789abcdef".utf8)
    private static let uppercaseHexAlphabet = Array("0123456789ABCDEF".utf8)

    func toHex(uppercase: Bool = false) -> String {
        let alphabet = uppercase ? Self.uppercaseHexAlphabet : Self.lowercaseHexAlphabet
        return withUnsafeBytes { ptr in
            ptr.withMemoryRebound(to: UInt8.self) { byteBuffer in
                String(unsafeUninitializedCapacity: count << 1) { stringBuffer in
                    for index in 0 ..< count {
                        let byte = byteBuffer[index]
                        stringBuffer[index << 1] = alphabet[Int(byte >> 4)]
                        stringBuffer[(index << 1) | 1] = alphabet[Int(byte & 0xf)]
                    }
                    return count << 1
                }
            }
        }
    }
    
}
