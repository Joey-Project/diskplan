import DiskplanScan

func fixtureValue<T>() -> T { fatalError() }

#sourceLocation(file:"DiskplanCompileFail-ForgeRuntimeFreshScanReceipt.swift",line:1007)
let forged = RuntimeFreshScanReceipt(
  captureID: fixtureValue(),
  kind: fixtureValue(),
  rootRequestDigest: fixtureValue(),
  volumeRequestDigest: fixtureValue(),
  rootBindingDigest: fixtureValue(),
  volumeBindingDigest: fixtureValue(),
  payload: fixtureValue(),
  session: fixtureValue(),
  leaseState: fixtureValue()
)
#sourceLocation()
