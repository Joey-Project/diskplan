import DiskplanCore
import DiskplanEngineCore
import Foundation

@main
struct DiskplanEngine {
  static func main() {
    if CommandLine.arguments == [CommandLine.arguments[0], "--version-json"] {
      print(
        "{\"component\":\"diskplan-engine\",\"product_version\":\"\(productVersion)\",\"protocol_major\":\(protocolMajor),\"protocol_minor\":\(protocolMinor)}"
      )
      return
    }
    guard CommandLine.arguments.count == 1 else {
      FileHandle.standardError.write(
        Data("usage: diskplan-engine [--version-json]\n".utf8)
      )
      Foundation.exit(64)
    }
    do {
      try EngineServer.run()
    } catch {
      FileHandle.standardError.write(Data("diskplan-engine: \(error)\n".utf8))
      Foundation.exit(1)
    }
  }
}
