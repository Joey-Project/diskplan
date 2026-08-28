import DiskplanScan
import Foundation

let requestDigest = try! EvidenceDigest(bytes: Data(repeating: 0, count: 32))

#sourceLocation(file:"DiskplanCompileFail-ForgeRequestID.swift",line:1001)
let forbiddenRequestID = ContentCollectionRequestID(rawValue: requestDigest)
#sourceLocation()
