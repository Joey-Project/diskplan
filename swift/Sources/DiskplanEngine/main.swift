import DiskplanEngineCore
import Foundation

@main
struct DiskplanEngine {
  static func main() {
    do {
      try EngineServer.run()
    } catch {
      FileHandle.standardError.write(Data("diskplan-engine: \(error)\n".utf8))
      Foundation.exit(1)
    }
  }

}
