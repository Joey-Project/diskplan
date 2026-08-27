import DiskplanCore
import Foundation
import Testing

@Test
func framingDistinguishesCleanEOFAndTruncation() throws {
    #expect(try FrameCodec.read(from: pipeHandle(Data())) == nil)
    #expect(throws: FrameError.truncatedPrefix(received: 3)) {
        try FrameCodec.read(from: pipeHandle(Data([0, 0, 0])))
    }
    #expect(throws: FrameError.truncatedPayload(expected: 3, received: 2)) {
        try FrameCodec.read(from: pipeHandle(Data([0, 0, 0, 3, 1, 2])))
    }
}

@Test
func framingRejectsOversizeBeforePayloadRead() {
    let length = UInt32(maximumFrameLength + 1)
    let prefix = Data([
        UInt8((length >> 24) & 0xff),
        UInt8((length >> 16) & 0xff),
        UInt8((length >> 8) & 0xff),
        UInt8(length & 0xff),
    ])
    #expect(throws: FrameError.oversized(length: maximumFrameLength + 1, maximum: maximumFrameLength)) {
        try FrameCodec.read(from: pipeHandle(prefix))
    }
}

@Test
func framingWritesBigEndianLength() throws {
    let pipe = Pipe()
    try FrameCodec.write(Data("abc".utf8), to: pipe.fileHandleForWriting)
    try pipe.fileHandleForWriting.close()
    let bytes = try pipe.fileHandleForReading.readToEnd()
    #expect(bytes == Data([0, 0, 0, 3]) + Data("abc".utf8))
}

private func pipeHandle(_ data: Data) throws -> FileHandle {
    let pipe = Pipe()
    try pipe.fileHandleForWriting.write(contentsOf: data)
    try pipe.fileHandleForWriting.close()
    return pipe.fileHandleForReading
}
