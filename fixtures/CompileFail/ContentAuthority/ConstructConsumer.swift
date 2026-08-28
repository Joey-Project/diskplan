import DiskplanScan

func fixtureValue<T>() -> T { fatalError() }

#sourceLocation(file:"DiskplanCompileFail-ConstructConsumer.swift",line:1002)
let forbiddenConsumer = ContentEvidenceConsumer(authority: fixtureValue())
#sourceLocation()
