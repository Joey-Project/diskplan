import CDiskplanMacOS
import Darwin

public struct NoMaterializationPolicy: Equatable, Sendable {
  fileprivate let installedValue: Int32
}

public struct MaterializationPolicyInstaller: Sendable {
  public typealias Setter = @Sendable () -> (result: Int32, error: Int32)
  public typealias Getter = @Sendable () -> (result: Int32, error: Int32)

  private let setOff: Setter
  private let readBack: Getter

  public init(
    setOff: @escaping Setter = {
      let result = dp_set_materialization_off()
      return (result, result == 0 ? 0 : errno)
    },
    readBack: @escaping Getter = {
      let result = dp_get_materialization_policy()
      return (result, result >= 0 ? 0 : errno)
    }
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
    return .known(NoMaterializationPolicy(installedValue: readResult.result))
  }
}
