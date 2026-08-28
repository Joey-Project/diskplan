import Foundation

public struct ProcessActivityRecord: Equatable, Sendable, Comparable {
  public let processID: Int32
  public let command: String?
  public let fileDescriptor: String?
  public let rawPath: Data

  public init(processID: Int32, command: String?, fileDescriptor: String?, rawPath: Data) {
    self.processID = processID
    self.command = command
    self.fileDescriptor = fileDescriptor
    self.rawPath = rawPath
  }

  public static func < (lhs: Self, rhs: Self) -> Bool {
    if lhs.processID != rhs.processID { return lhs.processID < rhs.processID }
    if lhs.rawPath != rhs.rawPath { return lhs.rawPath.lexicographicallyPrecedes(rhs.rawPath) }
    if lhs.fileDescriptor != rhs.fileDescriptor {
      return (lhs.fileDescriptor ?? "") < (rhs.fileDescriptor ?? "")
    }
    return (lhs.command ?? "") < (rhs.command ?? "")
  }
}

public enum LsofFieldParser {
  public static func parse(_ data: Data) -> Observation<[ProcessActivityRecord]> {
    let fields = data.split(separator: 0, omittingEmptySubsequences: true)
    var processID: Int32?
    var command: String?
    var descriptor: String?
    var records: [ProcessActivityRecord] = []
    for rawField in fields {
      let field = rawField.drop { $0 == UInt8(ascii: "\n") || $0 == UInt8(ascii: "\r") }
      guard let tag = field.first else { continue }
      let value = field.dropFirst()
      switch tag {
      case UInt8(ascii: "p"):
        guard let text = String(data: value, encoding: .utf8), let parsed = Int32(text) else {
          return .failed(reason: "lsof emitted an invalid process identifier", errorCode: nil)
        }
        processID = parsed
        command = nil
        descriptor = nil
      case UInt8(ascii: "c"):
        command = String(data: value, encoding: .utf8)
      case UInt8(ascii: "f"):
        descriptor = String(data: value, encoding: .utf8)
      case UInt8(ascii: "n"):
        guard let processID else {
          return .failed(reason: "lsof path field preceded its process field", errorCode: nil)
        }
        records.append(
          ProcessActivityRecord(
            processID: processID,
            command: command,
            fileDescriptor: descriptor,
            rawPath: Data(value)
          )
        )
      default:
        continue
      }
    }
    return .known(records.sorted())
  }
}

public protocol ProcessActivityCollecting: Sendable {
  /// Implementations run one bounded `lsof -nP -F0pcfn` snapshot, never recursive per-path probes.
  func collect(deadlineNanoseconds: UInt64) async -> Observation<[ProcessActivityRecord]>
}

public struct UnavailableProcessActivityCollector: ProcessActivityCollecting {
  public init() {}
  public func collect(deadlineNanoseconds: UInt64) async -> Observation<[ProcessActivityRecord]> {
    .unknown(reason: "bounded process snapshot collector is unavailable")
  }
}
