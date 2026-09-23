import Foundation
import RuntimeHost

guard CommandLine.arguments.count == 8 else {
    print("invalid_arguments")
    exit(2)
}

let role: VMRole = CommandLine.arguments[1] == "browser" ? .browser : .agent
let identity = VMImageIdentity(
    kernelSHA256: CommandLine.arguments[5],
    ramdiskSHA256: CommandLine.arguments[6],
    imageSHA256: CommandLine.arguments[7]
)

do {
    let configuration = try RuntimeVMConfiguration.make(
        role: role,
        kernel: URL(fileURLWithPath: CommandLine.arguments[2]),
        ramdisk: URL(fileURLWithPath: CommandLine.arguments[3]),
        image: URL(fileURLWithPath: CommandLine.arguments[4]),
        identity: identity
    )
    try configuration.validate()
    print("configuration_valid")
} catch {
    print("configuration_invalid")
    exit(1)
}
