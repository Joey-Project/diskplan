import Darwin
import DiskplanMacOS
import Foundation

public struct VMStatisticsSample: Equatable, Sendable {
  public let pageSize: UInt64
  public let freePages: UInt64
  public let activePages: UInt64
  public let inactivePages: UInt64
  public let wiredPages: UInt64
  public let speculativePages: UInt64
  public let compressedPages: UInt64
  public let purgeablePages: UInt64

  public init(
    pageSize: UInt64,
    freePages: UInt64,
    activePages: UInt64,
    inactivePages: UInt64,
    wiredPages: UInt64,
    speculativePages: UInt64,
    compressedPages: UInt64,
    purgeablePages: UInt64
  ) {
    self.pageSize = pageSize
    self.freePages = freePages
    self.activePages = activePages
    self.inactivePages = inactivePages
    self.wiredPages = wiredPages
    self.speculativePages = speculativePages
    self.compressedPages = compressedPages
    self.purgeablePages = purgeablePages
  }
}

public protocol VMStatisticsProviding: Sendable {
  func read() -> Observation<VMStatisticsSample>
}

public struct SystemVMStatisticsProvider: VMStatisticsProviding {
  public init() {}

  public func read() -> Observation<VMStatisticsSample> {
    let host = mach_host_self()
    defer { mach_port_deallocate(mach_task_self_, host) }

    var pageSize: vm_size_t = 0
    let pageStatus = host_page_size(host, &pageSize)
    guard pageStatus == KERN_SUCCESS else {
      return .failed(reason: "host_page_size failed", errorCode: Int32(pageStatus))
    }

    var statistics = vm_statistics64()
    var count = mach_msg_type_number_t(
      MemoryLayout<vm_statistics64_data_t>.size / MemoryLayout<integer_t>.size)
    let status = withUnsafeMutablePointer(to: &statistics) { pointer in
      pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
        host_statistics64(host, HOST_VM_INFO64, $0, &count)
      }
    }
    guard status == KERN_SUCCESS else {
      return .failed(reason: "host_statistics64 failed", errorCode: Int32(status))
    }

    return .known(
      VMStatisticsSample(
        pageSize: UInt64(pageSize),
        freePages: UInt64(statistics.free_count),
        activePages: UInt64(statistics.active_count),
        inactivePages: UInt64(statistics.inactive_count),
        wiredPages: UInt64(statistics.wire_count),
        speculativePages: UInt64(statistics.speculative_count),
        compressedPages: UInt64(statistics.compressor_page_count),
        purgeablePages: UInt64(statistics.purgeable_count)
      ))
  }
}

public protocol VMGlobalFactCollecting: Sendable {
  func collect() -> Observation<[String: UInt64]>
}

public struct PublicVMGlobalFactCollector: VMGlobalFactCollecting {
  public static let collectorID = "mach-host-vm-info64-v1"

  private let provider: any VMStatisticsProviding

  public init() {
    provider = SystemVMStatisticsProvider()
  }

  package init(provider: any VMStatisticsProviding) {
    self.provider = provider
  }

  public func collect() -> Observation<[String: UInt64]> {
    switch provider.read() {
    case .known(let sample):
      let pageCounts = [
        "free_bytes": sample.freePages,
        "active_bytes": sample.activePages,
        "inactive_bytes": sample.inactivePages,
        "wired_bytes": sample.wiredPages,
        "speculative_bytes": sample.speculativePages,
        "compressed_bytes": sample.compressedPages,
        "purgeable_bytes": sample.purgeablePages,
      ]
      var facts: [String: UInt64] = ["page_size_bytes": sample.pageSize]
      for (key, pages) in pageCounts {
        let (bytes, overflow) = pages.multipliedReportingOverflow(by: sample.pageSize)
        guard !overflow else {
          return .failed(reason: "VM byte count overflow", errorCode: EOVERFLOW)
        }
        facts[key] = bytes
      }
      return .known(facts)
    case .absent(let reason): return .absent(reason: reason)
    case .unknown(let reason): return .unknown(reason: reason)
    case .unreadable(let reason, let errorCode):
      return .unreadable(reason: reason, errorCode: errorCode)
    case .failed(let reason, let errorCode):
      return .failed(reason: reason, errorCode: errorCode)
    }
  }
}

public struct SwapUsageSample: Equatable, Sendable {
  public let totalBytes: UInt64
  public let usedBytes: UInt64
  public let availableBytes: UInt64
  public let encrypted: Bool

  public init(
    totalBytes: UInt64,
    usedBytes: UInt64,
    availableBytes: UInt64,
    encrypted: Bool
  ) {
    self.totalBytes = totalBytes
    self.usedBytes = usedBytes
    self.availableBytes = availableBytes
    self.encrypted = encrypted
  }
}

public protocol SwapUsageProviding: Sendable {
  func read() -> Observation<SwapUsageSample>
}

public struct SystemSwapUsageProvider: SwapUsageProviding {
  public init() {}

  public func read() -> Observation<SwapUsageSample> {
    var usage = xsw_usage()
    var size = MemoryLayout<xsw_usage>.size
    guard sysctlbyname("vm.swapusage", &usage, &size, nil, 0) == 0 else {
      return observationForPOSIXFailure(errno, operation: "sysctl vm.swapusage")
    }
    guard size == MemoryLayout<xsw_usage>.size else {
      return .failed(reason: "sysctl vm.swapusage returned an unexpected size", errorCode: EPROTO)
    }
    return .known(
      SwapUsageSample(
        totalBytes: UInt64(usage.xsu_total),
        usedBytes: UInt64(usage.xsu_used),
        availableBytes: UInt64(usage.xsu_avail),
        encrypted: usage.xsu_encrypted != 0
      ))
  }
}

public protocol SwapGlobalFactCollecting: Sendable {
  func collect() -> Observation<[String: UInt64]>
}

public struct PublicSwapGlobalFactCollector: SwapGlobalFactCollecting {
  public static let collectorID = "sysctl-vm-swapusage-v1"

  private let provider: any SwapUsageProviding

  public init() {
    provider = SystemSwapUsageProvider()
  }

  package init(provider: any SwapUsageProviding) {
    self.provider = provider
  }

  public func collect() -> Observation<[String: UInt64]> {
    switch provider.read() {
    case .known(let sample):
      return .known([
        "total_bytes": sample.totalBytes,
        "used_bytes": sample.usedBytes,
        "available_bytes": sample.availableBytes,
        "encrypted": sample.encrypted ? 1 : 0,
      ])
    case .absent(let reason): return .absent(reason: reason)
    case .unknown(let reason): return .unknown(reason: reason)
    case .unreadable(let reason, let errorCode):
      return .unreadable(reason: reason, errorCode: errorCode)
    case .failed(let reason, let errorCode):
      return .failed(reason: reason, errorCode: errorCode)
    }
  }
}

public protocol APFSSnapshotListing: Sendable {
  /// The descriptor must be a dedicated, already-open volume-root directory descriptor.
  /// Implementations may change only its enumeration offset and must not read file contents.
  func list(
    volumeFileDescriptor: Int32,
    maximumEntries: Int
  ) -> Observation<[Data]>
}

public struct PublicAPFSSnapshotLister: APFSSnapshotListing {
  public init() {}

  public func list(
    volumeFileDescriptor: Int32,
    maximumEntries: Int
  ) -> Observation<[Data]> {
    precondition(maximumEntries > 0)
    guard lseek(volumeFileDescriptor, 0, SEEK_SET) >= 0 else {
      return observationForPOSIXFailure(errno, operation: "reset snapshot enumeration cursor")
    }

    let bufferSize = 64 * 1_024
    var buffer = Data(count: bufferSize)
    var names: [Data] = []
    let probe = SnapshotListProbe()

    while true {
      let count: Int
      let capability = probe.list(fileDescriptor: volumeFileDescriptor, buffer: &buffer)
      switch capability.status {
      case .known:
        guard let value = capability.value else {
          return .failed(reason: "snapshot probe omitted its known value", errorCode: EPROTO)
        }
        count = Int(value)
      case .unsupported:
        return .absent(reason: capability.detail ?? "volume does not support snapshots")
      case .permissionDenied:
        return .unreadable(
          reason: capability.detail ?? "snapshot listing was denied",
          errorCode: capability.errorCode
        )
      case .unavailable:
        return .unknown(reason: capability.detail ?? "snapshot listing is unavailable")
      case .failed, .inconsistent:
        return .failed(
          reason: capability.detail ?? "snapshot listing failed",
          errorCode: capability.errorCode
        )
      }
      if count == 0 {
        return .known(Array(Set(names)).sorted(by: { $0.lexicographicallyPrecedes($1) }))
      }
      guard Int(count) <= maximumEntries,
        names.count <= maximumEntries - Int(count)
      else {
        return .failed(
          reason: "APFS snapshot count exceeded its structural limit", errorCode: EOVERFLOW)
      }
      switch SnapshotAttributeBufferParser.parse(buffer, entryCount: Int(count)) {
      case .known(let batch): names.append(contentsOf: batch)
      case .absent(let reason): return .absent(reason: reason)
      case .unknown(let reason): return .unknown(reason: reason)
      case .unreadable(let reason, let errorCode):
        return .unreadable(reason: reason, errorCode: errorCode)
      case .failed(let reason, let errorCode):
        return .failed(reason: reason, errorCode: errorCode)
      }
    }
  }
}

public enum SnapshotAttributeBufferParser {
  public static func parse(
    _ buffer: Data,
    entryCount: Int
  ) -> Observation<[Data]> {
    guard entryCount >= 0 else {
      return .failed(reason: "snapshot entry count is negative", errorCode: EPROTO)
    }
    var offset = 0
    var names: [Data] = []
    names.reserveCapacity(entryCount)
    for _ in 0..<entryCount {
      guard let recordLength = readUInt32(buffer, at: offset), recordLength >= 32 else {
        return .failed(reason: "snapshot attribute record is truncated", errorCode: EPROTO)
      }
      let recordEnd = offset + Int(recordLength)
      guard recordEnd >= offset, recordEnd <= buffer.count else {
        return .failed(reason: "snapshot attribute record has an invalid length", errorCode: EPROTO)
      }
      guard let returnedCommon = readUInt32(buffer, at: offset + 4),
        returnedCommon & UInt32(ATTR_CMN_NAME) != 0,
        let dataOffset = readInt32(buffer, at: offset + 24),
        let dataLength = readUInt32(buffer, at: offset + 28),
        dataOffset >= 0,
        dataLength > 0
      else {
        return .failed(reason: "snapshot name attribute is unavailable", errorCode: EPROTO)
      }
      let nameStart = offset + 24 + Int(dataOffset)
      let nameEnd = nameStart + Int(dataLength)
      guard nameStart >= offset, nameEnd > nameStart, nameEnd <= recordEnd,
        buffer[nameEnd - 1] == 0
      else {
        return .failed(reason: "snapshot name attribute has invalid bounds", errorCode: EPROTO)
      }
      let name = Data(buffer[nameStart..<(nameEnd - 1)])
      guard !name.isEmpty, !name.contains(0), !name.contains(UInt8(ascii: "/")),
        name != Data(".".utf8), name != Data("..".utf8)
      else {
        return .failed(reason: "snapshot name is not a valid raw path component", errorCode: EPROTO)
      }
      names.append(name)
      offset = recordEnd
    }
    return .known(names)
  }

  private static func readUInt32(_ data: Data, at offset: Int) -> UInt32? {
    guard offset >= 0, offset <= data.count, data.count - offset >= 4 else { return nil }
    return data.withUnsafeBytes {
      UInt32(littleEndian: $0.loadUnaligned(fromByteOffset: offset, as: UInt32.self))
    }
  }

  private static func readInt32(_ data: Data, at offset: Int) -> Int32? {
    guard let value = readUInt32(data, at: offset) else { return nil }
    return Int32(bitPattern: value)
  }
}

public struct RuntimeVolumeDescriptor: Equatable, Sendable, Comparable {
  public let volumeID: String
  public let fileDescriptor: Int32

  public init(volumeID: String, fileDescriptor: Int32) {
    precondition(!volumeID.isEmpty)
    self.volumeID = volumeID
    self.fileDescriptor = fileDescriptor
  }

  public static func < (lhs: Self, rhs: Self) -> Bool {
    if lhs.volumeID != rhs.volumeID { return lhs.volumeID < rhs.volumeID }
    return lhs.fileDescriptor < rhs.fileDescriptor
  }
}

public struct RuntimeGlobalFactSnapshot: Equatable, Sendable {
  public let vm: Observation<[String: UInt64]>
  public let swap: Observation<[String: UInt64]>
  public let apfsSnapshotsByVolume: [String: Observation<[Data]>]

  public init(
    vm: Observation<[String: UInt64]>,
    swap: Observation<[String: UInt64]>,
    apfsSnapshotsByVolume: [String: Observation<[Data]>]
  ) {
    self.vm = vm
    self.swap = swap
    self.apfsSnapshotsByVolume = apfsSnapshotsByVolume
  }
}

public struct RuntimeCollectorSnapshot: Equatable, Sendable {
  public let processActivity: ProcessActivityObservation
  public let globalFacts: RuntimeGlobalFactSnapshot

  public init(
    processActivity: ProcessActivityObservation,
    globalFacts: RuntimeGlobalFactSnapshot
  ) {
    self.processActivity = processActivity
    self.globalFacts = globalFacts
  }

  public var processAncestorIndex: ProcessActivityAncestorIndex {
    ProcessActivityAncestorIndex(activity: processActivity)
  }
}

public struct ProductionScanCollectorBundle: Sendable {
  private let processActivity: any ProcessActivityCollecting
  private let vm: any VMGlobalFactCollecting
  private let swap: any SwapGlobalFactCollecting
  private let snapshots: any APFSSnapshotListing
  private let maximumSnapshotEntriesPerVolume: Int

  public init(maximumSnapshotEntriesPerVolume: Int = 4_096) {
    precondition(maximumSnapshotEntriesPerVolume > 0)
    processActivity = BoundedLsofProcessActivityCollector()
    vm = PublicVMGlobalFactCollector()
    swap = PublicSwapGlobalFactCollector()
    snapshots = PublicAPFSSnapshotLister()
    self.maximumSnapshotEntriesPerVolume = maximumSnapshotEntriesPerVolume
  }

  package init(
    processActivity: any ProcessActivityCollecting,
    vm: any VMGlobalFactCollecting,
    swap: any SwapGlobalFactCollecting,
    snapshots: any APFSSnapshotListing,
    maximumSnapshotEntriesPerVolume: Int = 4_096
  ) {
    precondition(maximumSnapshotEntriesPerVolume > 0)
    self.processActivity = processActivity
    self.vm = vm
    self.swap = swap
    self.snapshots = snapshots
    self.maximumSnapshotEntriesPerVolume = maximumSnapshotEntriesPerVolume
  }

  public var collectorIDs: [String] {
    [
      BoundedLsofProcessActivityCollector.collectorID,
      PublicVMGlobalFactCollector.collectorID,
      PublicSwapGlobalFactCollector.collectorID,
      "fs-snapshot-list-v1",
    ].sorted()
  }

  /// Collects one process snapshot and public global facts without opening or reading scan paths.
  /// Snapshot descriptors are borrowed and must already refer to dedicated volume-root handles.
  public func collect(
    processDeadlineNanoseconds: UInt64,
    volumes: [RuntimeVolumeDescriptor]
  ) async -> RuntimeCollectorSnapshot {
    let vmFacts = vm.collect()
    let swapFacts = swap.collect()
    var snapshotFacts: [String: Observation<[Data]>] = [:]
    for volume in volumes.sorted() {
      if snapshotFacts[volume.volumeID] != nil {
        snapshotFacts[volume.volumeID] = .failed(
          reason: "duplicate volume identifier in collector input",
          errorCode: EINVAL
        )
        continue
      }
      snapshotFacts[volume.volumeID] = canonicalSnapshotNames(
        snapshots.list(
          volumeFileDescriptor: volume.fileDescriptor,
          maximumEntries: maximumSnapshotEntriesPerVolume
        )
      )
    }
    let activity = canonicalProcessActivity(
      await processActivity.collect(deadlineNanoseconds: processDeadlineNanoseconds)
    )
    return RuntimeCollectorSnapshot(
      processActivity: activity,
      globalFacts: RuntimeGlobalFactSnapshot(
        vm: vmFacts,
        swap: swapFacts,
        apfsSnapshotsByVolume: snapshotFacts
      )
    )
  }

  public func collectorConfiguration(
    processDeadlineNanoseconds: UInt64
  ) -> ScanCollectorConfiguration {
    ScanCollectorConfiguration(
      processActivityCollectorID: BoundedLsofProcessActivityCollector.collectorID,
      processActivityDeadlineNanoseconds: processDeadlineNanoseconds,
      globalFactCollectorIDs: collectorIDs.filter {
        $0 != BoundedLsofProcessActivityCollector.collectorID
      }
    )
  }

  private func canonicalSnapshotNames(
    _ observation: Observation<[Data]>
  ) -> Observation<[Data]> {
    switch observation {
    case .known(let names):
      return .known(Array(Set(names)).sorted(by: { $0.lexicographicallyPrecedes($1) }))
    case .absent(let reason): return .absent(reason: reason)
    case .unknown(let reason): return .unknown(reason: reason)
    case .unreadable(let reason, let errorCode):
      return .unreadable(reason: reason, errorCode: errorCode)
    case .failed(let reason, let errorCode):
      return .failed(reason: reason, errorCode: errorCode)
    }
  }

  private func canonicalProcessActivity(
    _ observation: ProcessActivityObservation
  ) -> ProcessActivityObservation {
    switch observation {
    case .complete(let records): return .complete(Array(Set(records)).sorted())
    case .degraded(let records, let reason):
      return .degraded(records: Array(Set(records)).sorted(), reason: reason)
    case .absent(let reason): return .absent(reason: reason)
    case .unknown(let reason): return .unknown(reason: reason)
    case .unreadable(let reason, let errorCode):
      return .unreadable(reason: reason, errorCode: errorCode)
    case .failed(let reason, let errorCode):
      return .failed(reason: reason, errorCode: errorCode)
    }
  }
}

private func observationForPOSIXFailure<Value: Equatable & Sendable>(
  _ code: Int32,
  operation: String
) -> Observation<Value> {
  switch code {
  case ENOENT, ENOTSUP, EOPNOTSUPP, ENOSYS:
    return .absent(reason: "\(operation) is unavailable")
  case EACCES, EPERM:
    return .unreadable(reason: "\(operation) was denied", errorCode: code)
  default:
    return .failed(reason: "\(operation) failed", errorCode: code)
  }
}
