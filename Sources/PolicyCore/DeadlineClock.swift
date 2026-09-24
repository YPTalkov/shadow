import Foundation
import Darwin

/// Unlike uptime, this monotonic clock advances while the Mac is asleep.
public enum DeadlineClock {
    private static let scale: Double = {
        var info = mach_timebase_info_data_t()
        mach_timebase_info(&info)
        return Double(info.numer) / Double(info.denom) / 1_000_000_000
    }()

    public static var now: TimeInterval { Double(mach_continuous_time()) * scale }
}
