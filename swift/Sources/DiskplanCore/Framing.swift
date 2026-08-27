import Foundation

public let maximumFrameLength = 16 * 1024 * 1024

public enum FrameError: Error, Equatable, CustomStringConvertible {
    case truncatedPrefix(received: Int)
    case oversized(length: Int, maximum: Int)
    case truncatedPayload(expected: Int, received: Int)
    case io(String)

    public var description: String {
        switch self {
        case .truncatedPrefix(let received):
            "truncated frame prefix: received \(received) of 4 bytes"
        case .oversized(let length, let maximum):
            "frame payload length \(length) exceeds maximum \(maximum)"
        case .truncatedPayload(let expected, let received):
            "truncated frame payload: received \(received) of \(expected) bytes"
        case .io(let detail):
            "I/O error: \(detail)"
        }
    }
}

public enum FrameCodec {
    public static func read(from handle: FileHandle) throws -> Data? {
        let prefix = try readExactly(upTo: 4, from: handle)
        if prefix.isEmpty {
            return nil
        }
        guard prefix.count == 4 else {
            throw FrameError.truncatedPrefix(received: prefix.count)
        }
        let length = prefix.reduce(0) { ($0 << 8) | Int($1) }
        guard length <= maximumFrameLength else {
            throw FrameError.oversized(length: length, maximum: maximumFrameLength)
        }
        let payload = try readExactly(upTo: length, from: handle)
        guard payload.count == length else {
            throw FrameError.truncatedPayload(expected: length, received: payload.count)
        }
        return payload
    }

    public static func write(_ payload: Data, to handle: FileHandle) throws {
        guard payload.count <= maximumFrameLength else {
            throw FrameError.oversized(length: payload.count, maximum: maximumFrameLength)
        }
        let length = UInt32(payload.count).bigEndian
        do {
            try withUnsafeBytes(of: length) { bytes in
                try handle.write(contentsOf: bytes)
            }
            try handle.write(contentsOf: payload)
        } catch {
            throw FrameError.io(String(describing: error))
        }
    }

    private static func readExactly(upTo count: Int, from handle: FileHandle) throws -> Data {
        var output = Data()
        output.reserveCapacity(count)
        do {
            while output.count < count {
                guard let chunk = try handle.read(upToCount: count - output.count), !chunk.isEmpty else {
                    break
                }
                output.append(chunk)
            }
            return output
        } catch {
            throw FrameError.io(String(describing: error))
        }
    }
}
