import CDiskplanMacOS
import Darwin

public struct NoMaterializationPolicy: Equatable, Sendable {
  fileprivate let installedValue: Int32
  fileprivate let readBack: MaterializationPolicyInstaller.Getter

  public static func == (lhs: Self, rhs: Self) -> Bool {
    lhs.installedValue == rhs.installedValue
  }

  func revalidateLive() -> Capability<NoMaterializationPolicy> {
    let result = readBack()
    guard result.result >= 0 else {
      return POSIXFailure.capability(
        result.error,
        operation: "read back live process dataless materialization policy"
      )
    }
    let off = Int32(IOPOL_MATERIALIZE_DATALESS_FILES_OFF)
    guard result.result & Int32(IOPOL_MATERIALIZE_DATALESS_FILES_BASIC_MASK) == off else {
      return Capability(
        status: .inconsistent,
        detail: "live materialization policy did not report OFF"
      )
    }
    return .known(self)
  }
}

public struct MaterializationPolicyInstaller: Sendable {
  public typealias Setter = @Sendable () -> (result: Int32, error: Int32)
  public typealias Getter = @Sendable () -> (result: Int32, error: Int32)

  private let setOff: Setter
  private let readBack: Getter

  public init() {
    self.init(
      setOff: {
        let result = dp_set_materialization_off()
        return (result, result == 0 ? 0 : errno)
      },
      readBack: {
        let result = dp_get_materialization_policy()
        return (result, result >= 0 ? 0 : errno)
      }
    )
  }

  init(
    setOff: @escaping Setter,
    readBack: @escaping Getter
  ) {
    self.setOff = setOff
    self.readBack = readBack
  }

  public func installBeforePathAccess() -> Capability<NoMaterializationPolicy> {
    let setResult = setOff()
    guard setResult.result == 0 else {
      return POSIXFailure.capability(
        setResult.error,
        operation: "set process dataless materialization policy OFF"
      )
    }
    let readResult = readBack()
    guard readResult.result >= 0 else {
      return POSIXFailure.capability(
        readResult.error,
        operation: "read back process dataless materialization policy"
      )
    }
    let off = Int32(IOPOL_MATERIALIZE_DATALESS_FILES_OFF)
    guard readResult.result & Int32(IOPOL_MATERIALIZE_DATALESS_FILES_BASIC_MASK) == off else {
      return Capability(
        status: .inconsistent,
        detail: "materialization policy readback did not report OFF"
      )
    }
    return .known(
      NoMaterializationPolicy(installedValue: readResult.result, readBack: readBack)
    )
  }
}
